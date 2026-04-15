import type { FastifyRequest, FastifyReply } from "fastify";
import { NWCClient } from "@getalby/sdk/nwc";
import { randomBytes, createHmac } from "node:crypto";
import { validatePreimage } from "@getalby/lightning-tools";
import { proxyUpstream } from "./proxy.js";
import { MACAROON_SECRET } from "./l402.js";

// --- JCS (RFC 8785) helpers ---
// Keys must be sorted in Unicode code-point order; for ASCII keys this is
// plain lexicographic order.  We only need this for our own objects, which
// all have ASCII keys, so a simple recursive sort is sufficient.

function sortKeysDeep(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  return Object.keys(value as object)
    .sort()
    .reduce<Record<string, unknown>>((acc, key) => {
      acc[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
      return acc;
    }, {});
}

function jcsSerialize(obj: unknown): string {
  return JSON.stringify(sortKeysDeep(obj));
}

// --- base64url (no padding) ---

function b64uEncode(str: string): string {
  return Buffer.from(str, "utf8").toString("base64url");
}

function b64uDecode(str: string): string {
  return Buffer.from(str, "base64url").toString("utf8");
}

// --- HMAC challenge binding ---
// Binds challengeId + url + amountSats + paymentHash together so none of
// those fields can be tampered with by the client.

function signChallenge(
  challengeId: string,
  url: string,
  amountSats: number,
  paymentHash: string,
): string {
  return createHmac("sha256", MACAROON_SECRET)
    .update(`${challengeId}|${url}|${amountSats}|${paymentHash}`)
    .digest("hex");
}

// --- Handler ---

export async function handleMPP(
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<void> {
  const authHeader = request.headers["authorization"];

  // --- Authenticated path: client retrying with preimage ---
  if (authHeader?.startsWith("Payment ")) {
    request.log.info("MPP Authorization header present — verifying payment");

    let credential: {
      challenge: {
        expires: string;
        id: string;
        intent: string;
        method: string;
        realm: string;
        request: string;
      };
      payload: { preimage: string };
    };
    try {
      credential = JSON.parse(b64uDecode(authHeader.slice(8)));
    } catch {
      return reply
        .status(400)
        .send({ error: "Malformed Authorization credential" });
    }

    const { challenge, payload: credPayload } = credential;
    const preimage = credPayload?.preimage;

    if (!preimage || !/^[0-9a-f]{64}$/.test(preimage)) {
      return reply.status(400).send({ error: "Invalid preimage format" });
    }

    // Check challenge expiry
    if (new Date(challenge.expires) < new Date()) {
      request.log.warn({ expires: challenge.expires }, "MPP challenge expired");
      return reply.status(401).send({ error: "Challenge expired" });
    }

    // Decode the echoed request object
    let requestObj: {
      amount: string;
      currency: string;
      description: string;
      externalId: string;
      methodDetails: { invoice: string; network: string; paymentHash: string };
    };
    try {
      requestObj = JSON.parse(b64uDecode(challenge.request));
    } catch {
      return reply
        .status(400)
        .send({ error: "Malformed challenge request field" });
    }

    // Decode externalId to recover upstream URL, amount, and HMAC sig
    let externalData: { amount: number; sig: string; url: string };
    try {
      externalData = JSON.parse(b64uDecode(requestObj.externalId));
    } catch {
      return reply.status(400).send({ error: "Malformed externalId" });
    }

    const { amount: amountSats, sig, url: upstreamUrl } = externalData;
    const paymentHash = requestObj.methodDetails.paymentHash;

    // Verify HMAC — ensures URL, amount, and paymentHash haven't been altered
    const expectedSig = signChallenge(
      challenge.id,
      upstreamUrl,
      amountSats,
      paymentHash,
    );
    if (sig !== expectedSig) {
      request.log.warn("MPP challenge HMAC mismatch — possible tampering");
      return reply.status(401).send({ error: "Invalid challenge signature" });
    }

    // Verify preimage against payment hash
    if (!validatePreimage(preimage, paymentHash)) {
      request.log.warn({ paymentHash }, "MPP preimage verification failed");
      return reply.status(401).send({ error: "Invalid preimage" });
    }

    request.log.info(
      { url: upstreamUrl },
      "MPP payment verified — proxying to upstream",
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

    const receipt = {
      challengeId: challenge.id,
      method: "lightning",
      reference: paymentHash,
      status: "success",
      timestamp: new Date().toISOString(),
    };
    reply.header("Payment-Receipt", b64uEncode(jcsSerialize(receipt)));

    return reply.send(body);
  }

  // --- Unauthenticated path — issue MPP challenge ---
  request.log.info("No MPP Authorization header — issuing challenge");

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
    "Creating invoice via NWC for MPP challenge",
  );

  const client = new NWCClient({ nostrWalletConnectUrl: nwc_url });
  try {
    const tx = await client.makeInvoice({
      amount: amountSats * 1000, // NWC uses millisats
      description: "MPP 402 proxy access",
    });

    const challengeId = randomBytes(16).toString("hex");
    const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 min
    const realm = request.headers.host
      ? `${request.protocol ?? "https"}://${request.headers.host}`
      : "https://402-proxy";

    const sig = signChallenge(
      challengeId,
      upstreamUrl.toString(),
      amountSats,
      tx.payment_hash,
    );

    // externalId is itself JCS-serialized + base64url-encoded so it travels
    // safely inside the outer request JSON and survives the client round-trip.
    const externalId = b64uEncode(
      jcsSerialize({ amount: amountSats, sig, url: upstreamUrl.toString() }),
    );

    const requestObj = {
      amount: String(amountSats),
      currency: "sat",
      description: "402 proxy access",
      externalId,
      methodDetails: {
        invoice: tx.invoice,
        network: "mainnet",
        paymentHash: tx.payment_hash,
      },
    };

    const requestParam = b64uEncode(jcsSerialize(requestObj));

    const wwwAuthenticate =
      `Payment id="${challengeId}", realm="${realm}", ` +
      `method="lightning", intent="charge", ` +
      `request="${requestParam}", expires="${expires}"`;

    request.log.info(
      { paymentHash: tx.payment_hash, challengeId },
      "MPP challenge issued",
    );

    return reply
      .status(402)
      .header("WWW-Authenticate", wwwAuthenticate)
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
