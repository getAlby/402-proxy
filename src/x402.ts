import type { FastifyRequest, FastifyReply } from "fastify";
import { createHmac } from "node:crypto";
import {
  HTTPFacilitatorClient,
  encodePaymentRequiredHeader,
  decodePaymentSignatureHeader,
  encodePaymentResponseHeader,
} from "@x402/core/http";
import type {
  SchemeNetworkServer,
  PaymentRequirements,
  PaymentRequired,
  Network,
  Price,
  AssetAmount,
} from "@x402/core/types";
import { MACAROON_SECRET } from "./l402.js";
import { proxyUpstream } from "./proxy.js";

// --- Constants ---

const ALBY_FACILITATOR_URL = "https://x402.albylabs.com";
const BITCOIN_MAINNET = "bip122:000000000019d6689c085ae165831e93" as const;

// --- Facilitator client ---

const facilitatorClient = new HTTPFacilitatorClient({
  url: ALBY_FACILITATOR_URL,
});

// --- Merchant registration cache ---

const merchantIdCache = new Map<string, string>();

async function getOrRegisterMerchantId(nwcUrl: string): Promise<string> {
  const cached = merchantIdCache.get(nwcUrl);
  if (cached) return cached;

  const res = await fetch(`${ALBY_FACILITATOR_URL}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ nwcSecret: nwcUrl }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`NWC registration failed (${res.status}): ${text}`);
  }
  const { merchantId } = (await res.json()) as { merchantId: string };
  merchantIdCache.set(nwcUrl, merchantId);
  return merchantId;
}

// --- HMAC helper (tamper-proof URL binding) ---

function signExtra(
  url: string,
  amountMsats: number,
  merchantId: string,
): string {
  return createHmac("sha256", MACAROON_SECRET)
    .update(`${url}|${amountMsats}|${merchantId}`)
    .digest("hex");
}

// --- LightningSchemeNetworkServer ---
// Adapted from getAlby/x402-facilitator demo (src/demo/lightning-server.ts).
// Changes vs original:
//   - No requestContext dependency (we call facilitatorClient.verify directly, so no
//     invoice-reuse trick is needed)
//   - Preserves url, sig, merchantId in enhanced extra for the client round-trip

class LightningSchemeNetworkServer implements SchemeNetworkServer {
  readonly scheme = "exact";

  constructor(private readonly facilitatorUrl: string) {}

  async parsePrice(price: Price, _network: Network): Promise<AssetAmount> {
    if (typeof price === "number") {
      return { amount: String(Math.round(price) * 1000), asset: "BTC" };
    }
    if (typeof price === "object" && "amount" in price && "asset" in price) {
      return { amount: String(price.amount), asset: "BTC" };
    }
    throw new Error(`Cannot parse price: ${JSON.stringify(price)}`);
  }

  async enhancePaymentRequirements(
    requirements: PaymentRequirements,
    _supportedKind: {
      x402Version: number;
      scheme: string;
      network: Network;
      extra?: Record<string, unknown>;
    },
    _facilitatorExtensions: string[],
  ): Promise<PaymentRequirements> {
    const extra = (requirements.extra ?? {}) as Record<string, unknown>;
    const merchantId = extra.merchantId as string | undefined;
    if (!merchantId) {
      throw new Error(
        "requirements.extra.merchantId is required for Lightning payments",
      );
    }

    const res = await fetch(`${this.facilitatorUrl}/invoice`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        amount: Number(requirements.amount), // millisatoshis
        merchantId,
        description: "x402 proxy access",
        network: requirements.network,
      }),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Invoice generation failed (${res.status}): ${text}`);
    }
    const { invoice } = (await res.json()) as { invoice: string };

    return {
      ...requirements,
      payTo: requirements.payTo || "anonymous",
      extra: {
        paymentMethod: "lightning",
        invoice,
        // Preserve these so the client sends them back in payment-signature,
        // allowing us to verify the HMAC and find the upstream URL.
        url: extra.url,
        sig: extra.sig,
        merchantId,
      },
    };
  }
}

const lightningScheme = new LightningSchemeNetworkServer(ALBY_FACILITATOR_URL);

// --- Handler ---

export async function handleX402(
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<void> {
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

    const extra = (payload.accepted.extra ?? {}) as Record<string, unknown>;
    const upstreamUrl = extra.url as string | undefined;
    const sig = extra.sig as string | undefined;
    const merchantId = extra.merchantId as string | undefined;

    if (!upstreamUrl || !sig || !merchantId) {
      return reply
        .status(400)
        .send({ error: "Missing url, sig, or merchantId in payment extra" });
    }

    const expectedSig = signExtra(
      upstreamUrl,
      Number(payload.accepted.amount),
      merchantId,
    );
    if (sig !== expectedSig) {
      request.log.warn("Payment extra HMAC mismatch — possible tampering");
      return reply.status(401).send({ error: "Invalid payment signature" });
    }

    const verifyResult = await facilitatorClient.verify(
      payload,
      payload.accepted,
    );
    if (!verifyResult.isValid) {
      request.log.warn(
        { reason: verifyResult.invalidReason },
        "Payment verification failed",
      );
      return reply
        .status(402)
        .send({ error: verifyResult.invalidMessage ?? "Payment not valid" });
    }

    request.log.info(
      { url: upstreamUrl },
      "Payment verified — proxying to upstream",
    );

    let body: Buffer;
    try {
      body = await proxyUpstream(request, upstreamUrl, reply);
    } catch (err) {
      request.log.error({ err, url: upstreamUrl }, "Upstream fetch failed");
      return reply
        .status(502)
        .send({ error: "Upstream fetch failed", detail: String(err) });
    }

    try {
      const settleResult = await facilitatorClient.settle(
        payload,
        payload.accepted,
      );
      reply.header(
        "PAYMENT-RESPONSE",
        encodePaymentResponseHeader(settleResult),
      );
    } catch (err) {
      // Settlement failure is non-fatal from the client's perspective — the
      // proxied response has already been prepared. Log and continue.
      request.log.error({ err }, "Payment settlement failed");
    }

    return reply.send(body);
  }

  // --- Unauthenticated path — issue x402 challenge ---
  request.log.info("No payment-signature header — issuing x402 challenge");

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
  const amountMsats = amountSats * 1000;

  let merchantId: string;
  try {
    merchantId = await getOrRegisterMerchantId(nwc_url);
  } catch (err) {
    request.log.error({ err }, "NWC registration failed");
    return reply
      .status(502)
      .send({ error: "Failed to register NWC wallet", detail: String(err) });
  }

  const sig = signExtra(urlStr, amountMsats, merchantId);

  const baseRequirements: PaymentRequirements = {
    scheme: "exact",
    network: BITCOIN_MAINNET,
    asset: "BTC",
    amount: String(amountMsats),
    payTo: "anonymous",
    maxTimeoutSeconds: 300,
    extra: { merchantId, url: urlStr, sig },
  };

  let enhanced: PaymentRequirements;
  try {
    enhanced = await lightningScheme.enhancePaymentRequirements(
      baseRequirements,
      { x402Version: 2, scheme: "exact", network: BITCOIN_MAINNET },
      [],
    );
  } catch (err) {
    request.log.error({ err }, "Invoice generation failed");
    return reply
      .status(502)
      .send({ error: "Failed to generate invoice", detail: String(err) });
  }

  const paymentRequired: PaymentRequired = {
    x402Version: 2,
    accepts: [enhanced],
    resource: { url: request.url, description: "Proxy access" },
  };

  request.log.info(
    { url: urlStr, amountMsats, merchantId },
    "Returning x402 challenge",
  );

  return reply
    .status(402)
    .header("PAYMENT-REQUIRED", encodePaymentRequiredHeader(paymentRequired))
    .send(paymentRequired);
}
