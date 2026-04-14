# 402 Proxy

A minimal HTTP proxy that gates upstream API access behind Lightning payments. It supports two protocols:

- **[L402](https://docs.lightning.engineering/the-lightning-network/l402)** — uses macaroons and `WWW-Authenticate` / `Authorization` headers
- **[x402](https://x402.org)** — uses `PAYMENT-REQUIRED` / `Payment-Signature` headers, settled via the [Alby x402 facilitator](https://x402.albylabs.com)

Unauthenticated requests receive a `402 Payment Required` challenge containing a Lightning invoice. Once the invoice is paid, the client authenticates and the proxy forwards the request to the upstream URL.

## For Testing Only

This is for testing only — the receiving wallet NWC URL is included in the request, as well as the real upstream URL, so if you inspect the URL you could extract the original endpoint and execute it for free.

## Setup

```bash
yarn install
yarn run dev        # development (tsx, no build step)
# or
yarn run build && yarn start   # production
```

The server listens on port `3000` by default. Set `PORT` to override.

## Endpoints

Both endpoints accept the same query parameters:

| Param     | Description                                                                                     |
| --------- | ----------------------------------------------------------------------------------------------- |
| `url`     | The encoded upstream URL to proxy to                                                            |
| `nwc_url` | An encoded [Nostr Wallet Connect](https://nwc.dev) connection string used to create the invoice |
| `amount`  | Amount in sats                                                                                  |

---

### `/l402` — L402 Protocol

#### Step 1 — Request a payment challenge

```bash
curl -v "http://localhost:3000/l402?url=https://example.com&nwc_url=nostr%2Bwalletconnect%3A%2F%2F...&amount=1"
```

Response: `402 Payment Required`

```
WWW-Authenticate: L402 macaroon="<macaroon>", invoice="<bolt11>"
```

The `macaroon` encodes the upstream URL, payment hash, and a 1-hour expiry, signed with an HMAC. Save it — you'll need it in step 3.

#### Step 2 — Pay the invoice

Pay the `bolt11` invoice using any Lightning wallet. After payment you receive a **preimage** (32-byte hex string).

#### Step 3 — Make the authenticated request

```bash
curl -v -H "Authorization: L402 <macaroon>:<preimage>" \
  "http://localhost:3000/l402?url=https://example.com&nwc_url=nostr%2Bwalletconnect%3A%2F%2F...&amount=1"
```

The proxy verifies the macaroon signature and that `SHA256(preimage) == paymentHash`, then forwards the request upstream. Query params are ignored on authenticated requests.

---

### `/x402` — x402 Protocol

#### Step 1 — Request a payment challenge

```bash
curl -v "http://localhost:3000/x402?url=https://example.com&nwc_url=nostr%2Bwalletconnect%3A%2F%2F...&amount=1"
```

Response: `402 Payment Required` with a JSON body and header:

```
PAYMENT-REQUIRED: <encoded payment requirements>
```

The JSON body contains the x402 payment requirements including a Lightning invoice in `accepts[0].extra.invoice`.

#### Step 2 — Pay the invoice

Pay the Lightning invoice. The Alby facilitator tracks the payment.

#### Step 3 — Make the authenticated request

Retry the request with a `Payment-Signature` header containing the encoded payment proof (as per the x402 spec). The proxy verifies the payment via the Alby facilitator, proxies the request upstream, and returns a `PAYMENT-RESPONSE` header with the settlement result.

---

## Notes

- The signing secret is generated randomly at startup, so macaroons (L402) and payment bindings (x402) are invalidated when the server restarts.
- L402 macaroons expire after **1 hour**.
- The `Authorization` header is stripped before forwarding to the upstream.
