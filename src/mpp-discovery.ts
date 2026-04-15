import type { FastifyRequest, FastifyReply } from "fastify";

const SERVICE_URL =
  process.env.SERVICE_URL ?? "https://402-proxy.albylabs.com";

export function handleMPPDiscovery(
  _request: FastifyRequest,
  reply: FastifyReply,
): void {
  reply.send({
    openapi: "3.1.0",
    info: { title: "402 Proxy", version: "1.0.0" },
    "x-service-info": {
      categories: ["proxy", "lightning", "payments"],
      docs: {
        homepage: "https://github.com/getAlby/402-proxy",
      },
    },
    servers: [{ url: SERVICE_URL }],
    paths: {
      "/mpp": {
        get: {
          summary: "Proxy an HTTP request gated by MPP lightning charge",
          description:
            "Pass `url`, `nwc_url`, and `amount` (sats) as query parameters. " +
            "The server issues a BOLT11 invoice; after payment the client retries " +
            "with `Authorization: Payment <credential>` containing the preimage.",
          "x-payment-info": {
            // Amount is caller-defined via the `amount` query param.
            // The runtime 402 challenge is the authoritative source of terms.
            amount: "variable",
            currency: "sat",
            description:
              "Lightning payment required to access the proxied upstream URL",
            intent: "charge",
            method: "lightning",
          },
          parameters: [
            {
              name: "url",
              in: "query",
              required: true,
              description: "Upstream URL to proxy to",
              schema: { type: "string", format: "uri" },
            },
            {
              name: "nwc_url",
              in: "query",
              required: true,
              description:
                "Nostr Wallet Connect URL used to create the invoice",
              schema: { type: "string" },
            },
            {
              name: "amount",
              in: "query",
              required: true,
              description: "Amount in satoshis",
              schema: { type: "integer", minimum: 1 },
            },
          ],
          responses: {
            "200": { description: "Upstream response (payment verified)" },
            "402": {
              description:
                "Payment Required — WWW-Authenticate header contains the MPP lightning charge challenge",
            },
            "400": {
              description: "Bad Request — missing or invalid parameters",
            },
            "502": { description: "Upstream or NWC error" },
          },
        },
      },
    },
  });
}
