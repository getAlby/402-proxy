import {
  createHmac,
  createHash,
  timingSafeEqual,
} from "node:crypto";

export interface MacaroonPayload {
  paymentHash: string; // hex — SHA256 of the preimage
  url: string;         // upstream URL embedded so tokens are resource-scoped
  amount: number;      // sats paid
  expiresAt: number;   // Unix seconds, TTL 1 hour
}

function toBase64Url(s: string): string {
  return Buffer.from(s).toString("base64url");
}

function fromBase64Url(s: string): string {
  return Buffer.from(s, "base64url").toString("utf8");
}

function sign(secret: string, payload: string): string {
  return createHmac("sha256", secret).update(payload).digest("hex");
}

export function issueMacaroon(
  secret: string,
  paymentHash: string,
  url: string,
  amount: number
): string {
  const payload: MacaroonPayload = {
    paymentHash,
    url,
    amount,
    expiresAt: Math.floor(Date.now() / 1000) + 3600, // 1 hour TTL
  };
  const encoded = toBase64Url(JSON.stringify(payload));
  const mac = sign(secret, encoded);
  return `${encoded}.${mac}`;
}

export function verifyMacaroon(
  secret: string,
  token: string
): MacaroonPayload | null {
  const dotIndex = token.lastIndexOf(".");
  if (dotIndex === -1) return null;

  const encoded = token.slice(0, dotIndex);
  const mac = token.slice(dotIndex + 1);

  // Constant-time comparison to prevent timing attacks
  const expectedMac = sign(secret, encoded);
  try {
    if (
      !timingSafeEqual(
        Buffer.from(mac, "hex"),
        Buffer.from(expectedMac, "hex")
      )
    ) {
      return null;
    }
  } catch {
    return null;
  }

  let payload: MacaroonPayload;
  try {
    payload = JSON.parse(fromBase64Url(encoded)) as MacaroonPayload;
  } catch {
    return null;
  }

  if (Math.floor(Date.now() / 1000) > payload.expiresAt) return null;

  return payload;
}

export function verifyPreimage(preimageHex: string, paymentHash: string): boolean {
  const hash = createHash("sha256")
    .update(Buffer.from(preimageHex, "hex"))
    .digest("hex");
  return hash === paymentHash;
}

export const L402_PREFIX = "L402 ";

export function parseL402Authorization(
  header: string
): { macaroon: string; preimage: string } | null {
  if (!header.startsWith(L402_PREFIX)) return null;
  const credentials = header.slice(L402_PREFIX.length);
  const colonIndex = credentials.indexOf(":");
  if (colonIndex === -1) return null;
  return {
    macaroon: credentials.slice(0, colonIndex),
    preimage: credentials.slice(colonIndex + 1),
  };
}

export function buildL402Challenge(macaroon: string, invoice: string): string {
  return `${L402_PREFIX}macaroon="${macaroon}", invoice="${invoice}"`;
}
