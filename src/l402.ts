import type { FastifyRequest, FastifyReply } from "fastify";
import { NWCClient } from "@getalby/sdk/nwc";
import { randomBytes } from "node:crypto";
import {
  issueL402Macaroon,
  makeL402AuthenticateHeader,
  parseL402Authorization,
  validatePreimage,
  verifyL402Macaroon,
} from "@getalby/lightning-tools";
import { proxyUpstream } from "./proxy.js";

export const MACAROON_SECRET = randomBytes(32).toString("hex");

type ProxyMacaroonPayload = { url: string };

export async function handleL402(
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<void> {
  const authHeader = request.headers["authorization"];

  // --- Authenticated path ---
  if (authHeader?.startsWith("L402")) {
    request.log.info("L402 Authorization header present — verifying");

    const parsed = parseL402Authorization(authHeader);
    if (!parsed) {
      request.log.warn(
        "Malformed Authorization header — missing colon separator",
      );
      return reply.status(400).send({
        error:
          "Invalid Authorization format; expected L402 <macaroon>:<preimage>",
      });
    }

    const { token, preimage } = parsed;

    const payload = await verifyL402Macaroon<ProxyMacaroonPayload>(
      MACAROON_SECRET,
      token,
    );
    if (!payload) {
      request.log.warn(
        "Macaroon verification failed — invalid signature or expired",
      );
      return reply.status(401).send({ error: "Invalid or expired macaroon" });
    }

    if (!validatePreimage(preimage, payload.paymentHash)) {
      request.log.warn(
        { paymentHash: payload.paymentHash },
        "Preimage verification failed",
      );
      return reply.status(401).send({ error: "Invalid preimage" });
    }

    request.log.info(
      { url: payload.url },
      "Auth verified — proxying to upstream",
    );

    let body: Buffer;
    try {
      body = await proxyUpstream(request, payload.url, reply);
    } catch (err) {
      request.log.error({ err, url: payload.url }, "Upstream fetch failed");
      return reply
        .status(502)
        .send({ error: "Upstream fetch failed", detail: String(err) });
    }
    return reply.send(body);
  }

  // --- Unauthenticated path — issue 402 challenge ---
  request.log.info("No Authorization header — issuing L402 challenge");

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

  request.log.info(
    { url: upstreamUrl.toString(), amountSats },
    "Creating invoice via NWC",
  );

  const client = new NWCClient({ nostrWalletConnectUrl: nwc_url });
  try {
    const tx = await client.makeInvoice({
      amount: amountSats * 1000, // NWC uses millisats
      description: "L402 proxy access",
    });

    request.log.info(
      { paymentHash: tx.payment_hash },
      "Invoice created — returning 402",
    );
    const macaroon = await issueL402Macaroon<ProxyMacaroonPayload>(
      MACAROON_SECRET,
      tx.payment_hash,
      { url: upstreamUrl.toString() },
    );

    const wwwAuthHeader = makeL402AuthenticateHeader({
      token: macaroon,
      invoice: tx.invoice,
    });

    return reply
      .status(402)
      .header("WWW-Authenticate", wwwAuthHeader)
      .send({ error: "Payment required" });
  } catch (err) {
    request.log.error({ err }, "NWC makeInvoice failed");
    return reply
      .status(502)
      .send({ error: "Failed to create invoice", detail: String(err) });
  } finally {
    client.close();
  }
}
