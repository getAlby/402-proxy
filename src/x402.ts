import type { FastifyRequest, FastifyReply } from "fastify";
import { NWCClient } from "@getalby/sdk/nwc";
import { createHash } from "node:crypto";
import {
  encodePaymentRequiredHeader,
  decodePaymentSignatureHeader,
  encodePaymentResponseHeader,
} from "@x402/core/http";
import type {
  PaymentRequirements,
  PaymentRequired,
  SettleResponse,
} from "@x402/core/types";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { recoverPublicKey, Signature } from "@noble/secp256k1";
import { decode } from "light-bolt11-decoder";
import { proxyUpstream } from "./proxy.js";

// x402 `exact` scheme on Bitcoin Lightning (`lnbtc`).
// Spec: https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_lnbtc.md
//
// The proxy acts as both resource server and facilitator: the invoice is created
// via NWC with a description hash that commits to the exact request, and the
// payment is verified locally from the preimage.

// --- Constants ---

const LNBTC_MAINNET = "lnbtc:000000000019d6689c085ae165831e93" as const;
const BOLT11_CURRENCY = "bc";
const MAX_TIMEOUT_SECONDS = 300;
const CLOCK_SKEW_SECONDS = 60;
const HTTP_PROFILE = "http:1";
// Headers forwarded upstream that change how the body is interpreted.
const BOUND_HEADERS = ["content-type"];

// --- Request binding (http:1) ---

const sha256Hex = (data: Uint8Array | string) =>
  createHash("sha256").update(data).digest("hex");

/** JCS (RFC 8785) for the binding object, which holds only strings, arrays and objects. */
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
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  throw new Error(`unsupported binding value ${String(value)}`);
}

/** Public URL of the request, as the client sent it (fly.io terminates TLS, see trustProxy). */
function getRequestUrl(request: FastifyRequest): string {
  return `${request.protocol}://${request.host}${request.url}`;
}

function computeRequestHash(request: FastifyRequest): string {
  const body = Buffer.isBuffer(request.body) ? request.body : Buffer.alloc(0);
  const binding = {
    domain: `x402:exact:lnbtc:bolt11:${HTTP_PROFILE}`,
    method: request.method,
    url: getRequestUrl(request),
    bodyHash: sha256Hex(body),
    headers: BOUND_HEADERS.map((name) => {
      const value = request.headers[name];
      if (typeof value !== "string") {
        return { name, valueHash: sha256Hex(new Uint8Array([0])) };
      }
      if (!/^[\x20-\x7e]*$/.test(value)) {
        throw new Error(`header ${name} has a non-ASCII value`);
      }
      return { name, valueHash: sha256Hex(`\x01${value.trim()}`) };
    }),
  };
  return sha256Hex(canonicalize(binding));
}

// --- BOLT11 ---

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/** 5-bit words to bytes, keeping a trailing partial byte (BOLT11 signing data). */
function wordsToBytes(words: number[]): Uint8Array {
  const bytes: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const word of words) {
    acc = (acc << 5) | word;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      bytes.push((acc >> bits) & 0xff);
    }
  }
  if (bits > 0) bytes.push((acc << (8 - bits)) & 0xff);
  return new Uint8Array(bytes);
}

/** Recover the compressed public key that signed a (checksum-valid) BOLT11 invoice. */
function recoverInvoiceSigner(paymentRequest: string): string {
  const pr = paymentRequest.toLowerCase();
  const separator = pr.lastIndexOf("1");
  const hrp = pr.slice(0, separator);
  const words = [...pr.slice(separator + 1, -6)].map((c) =>
    BECH32_CHARSET.indexOf(c),
  );
  const signature = wordsToBytes(words.slice(-104));
  const message = Buffer.concat([
    Buffer.from(hrp, "utf8"),
    wordsToBytes(words.slice(0, -104)),
  ]);
  return Buffer.from(
    recoverPublicKey(
      createHash("sha256").update(message).digest(),
      Signature.fromCompact(signature.slice(0, 64)),
      signature[64],
      true,
    ),
  ).toString("hex");
}

type DecodedInvoice = {
  paymentHash: string;
  payee: string;
  amountMsat: string;
  descriptionHash: string;
  currency: string;
  timestamp: number;
  expiry: number;
};

class X402Error extends Error {
  constructor(
    readonly reason: string,
    message: string,
  ) {
    super(`${reason}: ${message}`);
  }
}

function decodeInvoice(invoice: string): DecodedInvoice {
  let sections: { name: string; value?: unknown }[];
  let payee: string;
  try {
    sections = decode(invoice).sections as typeof sections;
    payee = recoverInvoiceSigner(invoice);
  } catch (err) {
    throw new X402Error("invalid_exact_lnbtc_invoice_decode_failed", String(err));
  }
  const all = (name: string) => sections.filter((s) => s.name === name);
  const get = (name: string) => all(name)[0]?.value;

  const descriptionHashes = all("description_hash");
  if (descriptionHashes.length !== 1 || all("description").length) {
    throw new X402Error(
      "invalid_exact_lnbtc_invoice_description",
      "invoice must contain exactly one description hash and no description",
    );
  }
  const payeeTag = get("payee");
  if (payeeTag !== undefined && payeeTag !== payee) {
    throw new X402Error(
      "invalid_exact_lnbtc_invoice_payee_mismatch",
      "invoice payee tag does not match its signer",
    );
  }
  return {
    paymentHash: get("payment_hash") as string,
    payee,
    amountMsat: get("amount") as string,
    descriptionHash: descriptionHashes[0].value as string,
    currency: (get("coin_network") as { bech32?: string } | undefined)
      ?.bech32 as string,
    timestamp: get("timestamp") as number,
    // BOLT11 default when the invoice has no `x` field
    expiry: (get("expiry") as number | undefined) ?? 3600,
  };
}

/**
 * Invoice checks shared by challenge issuance and settlement. `graceSeconds`
 * allows a paid-but-expired invoice to settle shortly after expiry.
 */
function validateInvoice(
  invoice: DecodedInvoice,
  expected: { requestHash: string; payTo: string; amountMsat: string },
  graceSeconds: number,
) {
  if (invoice.descriptionHash !== expected.requestHash) {
    throw new X402Error(
      "invalid_exact_lnbtc_invoice_request_mismatch",
      "invoice description hash does not commit to this request",
    );
  }
  if (invoice.payee !== expected.payTo) {
    throw new X402Error(
      "invalid_exact_lnbtc_invoice_payee_mismatch",
      `invoice signed by ${invoice.payee}, expected ${expected.payTo}`,
    );
  }
  if (invoice.currency !== BOLT11_CURRENCY) {
    throw new X402Error(
      "invalid_exact_lnbtc_invoice_currency_mismatch",
      `invoice currency ${invoice.currency} does not match ${LNBTC_MAINNET}`,
    );
  }
  if (invoice.amountMsat !== expected.amountMsat) {
    throw new X402Error(
      "invalid_exact_lnbtc_invoice_amount_mismatch",
      `invoice amount ${invoice.amountMsat} msat, expected ${expected.amountMsat}`,
    );
  }
  if (invoice.expiry !== MAX_TIMEOUT_SECONDS) {
    throw new X402Error(
      "invalid_exact_lnbtc_invoice_expiry_mismatch",
      `invoice expiry ${invoice.expiry}s, expected ${MAX_TIMEOUT_SECONDS}s`,
    );
  }
  const now = Math.floor(Date.now() / 1000);
  if (invoice.timestamp > now + CLOCK_SKEW_SECONDS) {
    throw new X402Error(
      "invalid_exact_lnbtc_invoice_created_in_future",
      `invoice created at ${invoice.timestamp}`,
    );
  }
  if (now > invoice.timestamp + invoice.expiry + graceSeconds) {
    throw new X402Error(
      "invalid_exact_lnbtc_invoice_expired",
      "invoice has expired",
    );
  }
}

// --- Replay store ---
// NOTE: in-memory, so a restart forgets consumed payment hashes. The spec
// requires a restart-durable store; acceptable for this test-only proxy.

const REPLAY_RETENTION_SECONDS = 60 * 60;
const settledPayments = new Map<string, number>(); // key -> retain until (unix s)

function claimPayment(key: string, invoice: DecodedInvoice): boolean {
  const now = Math.floor(Date.now() / 1000);
  for (const [k, until] of settledPayments) {
    if (until < now) settledPayments.delete(k);
  }
  if (settledPayments.has(key)) return false;
  settledPayments.set(
    key,
    invoice.timestamp +
      invoice.expiry +
      CLOCK_SKEW_SECONDS +
      REPLAY_RETENTION_SECONDS,
  );
  return true;
}

// --- Settlement ---

function buildRequirements(args: {
  amountMsat: string;
  payTo: string;
  requestHash: string;
  invoice: string;
}): PaymentRequirements {
  return {
    scheme: "exact",
    network: LNBTC_MAINNET,
    asset: "BTC",
    amount: args.amountMsat,
    payTo: args.payTo,
    maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
    extra: {
      assetTransferMethod: "bolt11",
      paymentFlow: "upfront",
      requestHash: args.requestHash,
      requestBindingProfile: HTTP_PROFILE,
      requestBindingParams: { headers: BOUND_HEADERS },
      invoice: args.invoice,
    },
  };
}

/**
 * Validate the payment proof against the request being executed (spec
 * "Facilitator Validation") and consume it. Returns the settled payment hash.
 */
async function settle(
  payload: ReturnType<typeof decodePaymentSignatureHeader>,
  expected: { requestHash: string; amountMsat: string },
  nwcClient: NWCClient,
): Promise<string> {
  const accepted = payload.accepted;
  const extra = (accepted.extra ?? {}) as Record<string, unknown>;

  if (accepted.scheme !== "exact") {
    throw new X402Error("unsupported_scheme", String(accepted.scheme));
  }
  if (accepted.network !== LNBTC_MAINNET) {
    throw new X402Error("network_mismatch", String(accepted.network));
  }
  if (accepted.asset !== "BTC") {
    throw new X402Error("invalid_exact_lnbtc_asset", String(accepted.asset));
  }
  if (accepted.amount !== expected.amountMsat) {
    throw new X402Error(
      "invalid_exact_lnbtc_amount_mismatch",
      String(accepted.amount),
    );
  }
  if (accepted.maxTimeoutSeconds !== MAX_TIMEOUT_SECONDS) {
    throw new X402Error(
      "invalid_exact_lnbtc_max_timeout_mismatch",
      String(accepted.maxTimeoutSeconds),
    );
  }
  if (
    typeof accepted.payTo !== "string" ||
    !/^0[23][0-9a-f]{64}$/.test(accepted.payTo)
  ) {
    throw new X402Error(
      "invalid_exact_lnbtc_pay_to_malformed",
      String(accepted.payTo),
    );
  }
  if (
    extra.assetTransferMethod !== undefined &&
    extra.assetTransferMethod !== "bolt11"
  ) {
    throw new X402Error(
      "invalid_exact_lnbtc_asset_transfer_method",
      String(extra.assetTransferMethod),
    );
  }
  if (extra.paymentFlow !== "upfront") {
    throw new X402Error(
      "invalid_exact_lnbtc_payment_flow",
      String(extra.paymentFlow),
    );
  }
  if (
    typeof extra.requestHash !== "string" ||
    typeof extra.requestBindingProfile !== "string" ||
    typeof extra.requestBindingParams !== "object" ||
    extra.requestBindingParams === null
  ) {
    throw new X402Error(
      "invalid_exact_lnbtc_request_binding",
      "missing request binding fields",
    );
  }
  if (
    extra.requestHash !== expected.requestHash ||
    extra.requestBindingProfile !== HTTP_PROFILE ||
    canonicalize(extra.requestBindingParams) !==
      canonicalize({ headers: BOUND_HEADERS })
  ) {
    throw new X402Error(
      "invalid_exact_lnbtc_request_mismatch",
      "accepted request binding does not match this request",
    );
  }
  if (typeof extra.invoice !== "string" || !extra.invoice) {
    throw new X402Error(
      "invalid_exact_lnbtc_invoice_missing",
      "accepted.extra.invoice is empty",
    );
  }

  const invoice = decodeInvoice(extra.invoice);
  validateInvoice(
    invoice,
    {
      requestHash: expected.requestHash,
      payTo: accepted.payTo,
      amountMsat: expected.amountMsat,
    },
    CLOCK_SKEW_SECONDS,
  );

  const preimage = (payload.payload as { preimage?: unknown }).preimage;
  if (preimage === undefined) {
    throw new X402Error("invalid_exact_lnbtc_preimage_missing", "no preimage");
  }
  if (typeof preimage !== "string" || !/^[0-9a-f]*$/.test(preimage)) {
    throw new X402Error(
      "invalid_exact_lnbtc_preimage_malformed",
      "preimage must be lowercase hex",
    );
  }
  if (preimage.length !== 64) {
    throw new X402Error(
      "invalid_exact_lnbtc_preimage_length",
      "preimage must be 32 bytes",
    );
  }
  if (sha256Hex(Buffer.from(preimage, "hex")) !== invoice.paymentHash) {
    throw new X402Error(
      "invalid_exact_lnbtc_preimage_hash_mismatch",
      "preimage does not hash to the invoice payment hash",
    );
  }

  // payTo comes from the client echo; make sure the invoice was issued by the
  // receiving wallet (and not a self-issued invoice signed by another key).
  const tx = await nwcClient
    .lookupInvoice({ payment_hash: invoice.paymentHash })
    .catch(() => undefined);
  if (tx?.type !== "incoming" || tx.invoice !== extra.invoice) {
    throw new X402Error(
      "invalid_exact_lnbtc_invoice_payee_mismatch",
      "invoice was not issued by the receiving wallet",
    );
  }

  if (!claimPayment(`${LNBTC_MAINNET}:${invoice.paymentHash}`, invoice)) {
    throw new X402Error("duplicate_settlement", "payment already used");
  }
  return invoice.paymentHash;
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

  // The request hash covers the full request URL (including url, nwc_url and
  // amount), so the paid retry can only execute the request that was paid for.
  let requestHash: string;
  try {
    requestHash = computeRequestHash(request);
  } catch (err) {
    return reply.status(400).send({ error: String(err) });
  }

  const sigHeader = request.headers["payment-signature"] as string | undefined;

  // --- Authenticated path: client retrying with payment proof ---
  if (sigHeader) {
    request.log.info(
      "payment-signature header present — verifying x402 payment",
    );

    let payload;
    try {
      payload = decodePaymentSignatureHeader(sigHeader);
    } catch (err) {
      request.log.warn({ err }, "Failed to decode payment-signature header");
      return reply
        .status(400)
        .send({ error: "Malformed payment-signature header" });
    }

    const client = new NWCClient({ nostrWalletConnectUrl: nwc_url });
    let paymentHash: string;
    try {
      paymentHash = await settle(payload, { requestHash, amountMsat }, client);
    } catch (err) {
      const reason = err instanceof X402Error ? err.reason : "unexpected_error";
      request.log.warn({ reason, err: String(err) }, "Payment settlement failed");
      const settleResponse: SettleResponse = {
        success: false,
        errorReason: reason,
        errorMessage: String(err),
        transaction: "",
        network: LNBTC_MAINNET,
      };
      return reply
        .status(402)
        .header("PAYMENT-RESPONSE", encodePaymentResponseHeader(settleResponse))
        .send({ error: String(err) });
    } finally {
      client.close();
    }

    request.log.info(
      { url: urlStr, paymentHash },
      "Payment settled — proxying to upstream",
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

    const settleResponse: SettleResponse = {
      success: true,
      transaction: paymentHash,
      network: LNBTC_MAINNET,
    };
    reply.header(
      "PAYMENT-RESPONSE",
      encodePaymentResponseHeader(settleResponse),
    );
    return reply.send(body);
  }

  // --- Unauthenticated path — issue x402 challenge ---
  request.log.info("No payment-signature header — issuing x402 challenge");

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

  const client = new NWCClient({ nostrWalletConnectUrl: nwc_url });
  let requirements: PaymentRequirements;
  try {
    const tx = await client.makeInvoice({
      amount: Number(amountMsat),
      description_hash: requestHash,
      expiry: MAX_TIMEOUT_SECONDS,
    });
    const invoice = decodeInvoice(tx.invoice);
    validateInvoice(
      invoice,
      { requestHash, payTo: invoice.payee, amountMsat },
      0,
    );
    requirements = buildRequirements({
      amountMsat,
      payTo: invoice.payee,
      requestHash,
      invoice: tx.invoice,
    });
  } catch (err) {
    request.log.error({ err }, "Invoice generation failed");
    return reply
      .status(502)
      .send({ error: "Failed to generate invoice", detail: String(err) });
  } finally {
    client.close();
  }

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
