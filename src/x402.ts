import type { FastifyRequest, FastifyReply } from "fastify";
import { NWCClient } from "@getalby/sdk/nwc";
import { createHash } from "node:crypto";
import { validatePreimage } from "@getalby/lightning-tools";
import {
  encodePaymentRequiredHeader,
  decodePaymentSignatureHeader,
  encodePaymentResponseHeader,
} from "@x402/core/http";
import type { PaymentRequired, PaymentRequirements } from "@x402/core/types";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { proxyUpstream } from "./proxy.js";

// x402 `exact` scheme on Bitcoin Lightning (`lnbtc`):
// https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_lnbtc.md
// The invoice's description hash commits to the exact request. We create the
// invoice via NWC, so the payment is verified against the receiving wallet
// (lookup_invoice) and the preimage — no facilitator needed.

// --- Constants ---

const LNBTC_MAINNET = "lnbtc:000000000019d6689c085ae165831e93" as const;
const MAX_TIMEOUT_SECONDS = 300;
const CLOCK_SKEW_SECONDS = 60;
// Headers forwarded upstream that change how the body is interpreted.
const BOUND_HEADERS = ["content-type"];
// Public origin the request binding covers (fly.io terminates TLS, so the app
// can't see the scheme clients used).
const PUBLIC_URL = (
  process.env.PUBLIC_URL ?? "https://402-proxy.albylabs.com"
).replace(/\/+$/, "");

// --- Request binding (http:1) ---

const sha256Hex = (data: Uint8Array | string) =>
  createHash("sha256").update(data).digest("hex");

/** JCS (RFC 8785) for the binding object, which holds only strings and arrays/objects of them. */
function canonicalize(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalize((value as Record<string, unknown>)[key])}`,
      )
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function getRequestUrl(request: FastifyRequest): string {
  return `${PUBLIC_URL}${request.url}`;
}

function computeRequestHash(request: FastifyRequest): string {
  const body = Buffer.isBuffer(request.body) ? request.body : Buffer.alloc(0);
  return sha256Hex(
    canonicalize({
      domain: "x402:exact:lnbtc:bolt11:http:1",
      method: request.method,
      url: getRequestUrl(request),
      bodyHash: sha256Hex(body),
      headers: BOUND_HEADERS.map((name) => {
        const value = request.headers[name];
        return {
          name,
          valueHash:
            typeof value === "string"
              ? sha256Hex(`\x01${value.trim()}`)
              : sha256Hex(new Uint8Array([0])),
        };
      }),
    }),
  );
}

// --- Replay protection ---
// NOTE: in-memory, so a restart forgets used payment hashes. Fine for this
// test-only proxy; the spec requires a durable store.

const usedPayments = new Map<string, number>(); // payment hash -> keep until (unix s)

function claimPayment(paymentHash: string, keepUntil: number): boolean {
  const now = Math.floor(Date.now() / 1000);
  for (const [hash, until] of usedPayments) {
    if (until < now) usedPayments.delete(hash);
  }
  if (usedPayments.has(paymentHash)) return false;
  usedPayments.set(paymentHash, keepUntil);
  return true;
}

/**
 * Check the payment proof against the request being executed. Returns the
 * payment hash, or throws with the reason.
 */
async function verifyPayment(
  sigHeader: string,
  expected: { requestHash: string; amountMsat: string },
  client: NWCClient,
): Promise<string> {
  const { accepted, payload } = decodePaymentSignatureHeader(sigHeader);
  const extra = (accepted.extra ?? {}) as Record<string, unknown>;
  const preimage = (payload as { preimage?: unknown }).preimage;

  if (
    accepted.scheme !== "exact" ||
    accepted.network !== LNBTC_MAINNET ||
    accepted.amount !== expected.amountMsat ||
    extra.paymentFlow !== "upfront"
  ) {
    throw new Error("payment terms do not match");
  }
  // Recomputed from the actual request, so a proof only works for the request it paid for.
  if (
    extra.requestHash !== expected.requestHash ||
    canonicalize(extra.requestBindingParams) !==
      canonicalize({ headers: BOUND_HEADERS })
  ) {
    throw new Error("invalid_exact_lnbtc_request_mismatch");
  }
  if (typeof extra.invoice !== "string" || typeof preimage !== "string") {
    throw new Error("missing invoice or preimage");
  }

  // The receiving wallet confirms it issued this invoice, for this request and amount.
  const tx = await client.lookupInvoice({ invoice: extra.invoice });
  if (
    tx.type !== "incoming" ||
    tx.invoice !== extra.invoice ||
    tx.description_hash !== expected.requestHash ||
    String(tx.amount) !== expected.amountMsat
  ) {
    throw new Error("invoice was not issued for this request");
  }
  if (!/^[0-9a-f]{64}$/.test(preimage) || !validatePreimage(preimage, tx.payment_hash)) {
    throw new Error("invalid_exact_lnbtc_preimage_hash_mismatch");
  }
  // Paid-but-expired grace period, then keep the hash for another hour.
  const deadline = tx.expires_at + CLOCK_SKEW_SECONDS;
  if (Math.floor(Date.now() / 1000) > deadline) {
    throw new Error("invalid_exact_lnbtc_invoice_expired");
  }
  if (!claimPayment(tx.payment_hash, deadline + 3600)) {
    throw new Error("duplicate_settlement");
  }
  return tx.payment_hash;
}

// --- Handler ---

export async function handleX402(
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<void> {
  const query = request.query as Record<string, string>;
  const { nwc_url, url, amount: amountStr } = query;

  if (!nwc_url || !url || !amountStr) {
    request.log.warn(
      { nwc_url: !!nwc_url, url: !!url, amount: !!amountStr },
      "Missing required query params",
    );
    return reply.status(400).send({
      error: "Missing required query params: nwc_url, url, amount",
    });
  }

  const amountSats = parseInt(amountStr, 10);
  if (!Number.isInteger(amountSats) || amountSats <= 0) {
    request.log.warn({ amountStr }, "Invalid amount param");
    return reply
      .status(400)
      .send({ error: "amount must be a positive integer (sats)" });
  }

  let upstreamUrl: URL;
  try {
    upstreamUrl = new URL(url);
  } catch {
    request.log.warn({ url }, "Invalid url param");
    return reply.status(400).send({ error: "Invalid url parameter" });
  }

  const urlStr = upstreamUrl.toString();
  const amountMsat = String(amountSats * 1000);
  // Covers the full request URL (incl. url, nwc_url and amount), method and body.
  const requestHash = computeRequestHash(request);

  const sigHeader = request.headers["payment-signature"] as string | undefined;
  const client = new NWCClient({ nostrWalletConnectUrl: nwc_url });

  // --- Authenticated path: client retrying with payment proof ---
  if (sigHeader) {
    request.log.info(
      "payment-signature header present — verifying x402 payment",
    );

    let paymentHash: string;
    try {
      paymentHash = await verifyPayment(
        sigHeader,
        { requestHash, amountMsat },
        client,
      );
    } catch (err) {
      request.log.warn({ err: String(err) }, "Payment verification failed");
      return reply.status(402).send({ error: String(err) });
    } finally {
      client.close();
    }

    request.log.info(
      { url: urlStr, paymentHash },
      "Payment verified — proxying to upstream",
    );

    let body: Buffer;
    try {
      body = await proxyUpstream(request, urlStr, reply);
    } catch (err) {
      request.log.error({ err, url: urlStr }, "Upstream fetch failed");
      return reply
        .status(502)
        .send({ error: "Upstream fetch failed", detail: String(err) });
    }

    reply.header(
      "PAYMENT-RESPONSE",
      encodePaymentResponseHeader({
        success: true,
        transaction: paymentHash,
        network: LNBTC_MAINNET,
      }),
    );
    return reply.send(body);
  }

  // --- Unauthenticated path — issue x402 challenge ---
  request.log.info("No payment-signature header — issuing x402 challenge");

  let requirements: PaymentRequirements;
  try {
    const [info, tx] = await Promise.all([
      client.getInfo(),
      client.makeInvoice({
        amount: amountSats * 1000, // NWC uses millisats
        description_hash: requestHash,
        expiry: MAX_TIMEOUT_SECONDS,
      }),
    ]);
    requirements = {
      scheme: "exact",
      network: LNBTC_MAINNET,
      asset: "BTC",
      amount: amountMsat,
      payTo: info.pubkey,
      maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
      extra: {
        paymentFlow: "upfront",
        requestHash,
        requestBindingProfile: "http:1",
        requestBindingParams: { headers: BOUND_HEADERS },
        invoice: tx.invoice,
      },
    };
  } catch (err) {
    request.log.error({ err }, "Invoice generation failed");
    return reply
      .status(502)
      .send({ error: "Failed to generate invoice", detail: String(err) });
  } finally {
    client.close();
  }

  const { bazaar } = declareDiscoveryExtension({
    input: { url: urlStr, nwc_url, amount: amountSats },
    inputSchema: {
      properties: {
        url: { type: "string", format: "uri", description: "Upstream URL to proxy" },
        nwc_url: { type: "string", description: "Nostr Wallet Connect URL (NIP-47) used to create the Lightning invoice" },
        amount: { type: "integer", minimum: 1, description: "Amount in satoshis" },
      },
      required: ["url", "nwc_url", "amount"],
    },
    output: {
      schema: { description: "The upstream HTTP response body, forwarded verbatim after payment is verified" },
      example: "Upstream response body (format depends on the proxied URL)",
    },
  });

  const paymentRequired: PaymentRequired = {
    x402Version: 2,
    accepts: [requirements],
    resource: { url: getRequestUrl(request), description: "Proxy access" },
    extensions: { bazaar },
  };

  request.log.info(
    { url: urlStr, amountMsat, payTo: requirements.payTo },
    "Returning x402 challenge",
  );

  return reply
    .status(402)
    .header("PAYMENT-REQUIRED", encodePaymentRequiredHeader(paymentRequired))
    .send(paymentRequired);
}
