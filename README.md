# L402 Proxy

A minimal HTTP proxy that gates upstream API access behind Lightning payments using the [L402 protocol](https://docs.lightning.engineering/the-lightning-network/l402).

Unauthenticated requests receive a `402 Payment Required` challenge containing a Lightning invoice. Once the invoice is paid, the client uses the preimage to authenticate and the proxy forwards the request to the upstream URL.

## For Testing Only

This is for testing only - the receiving wallet NWC url is included in the request, as well as the real URL, so if you actually look at the URL you could extract the original endpoint and execute it for free.

## Setup

```bash
yarn install
yarn run dev        # development (tsx, no build step)
# or
yarn run build && yarn start   # production
```

The server listens on port `3000` by default. Set `PORT` to override.

## Usage

### Step 1 — Request a payment challenge

Send any request to the proxy with three query params:

| Param     | Description                                                                                     |
| --------- | ----------------------------------------------------------------------------------------------- |
| `url`     | The encoded upstream URL to proxy to                                                            |
| `nwc_url` | An encoded [Nostr Wallet Connect](https://nwc.dev) connection string used to create the invoice |
| `amount`  | Amount in sats                                                                                  |

```bash
curl -v "http://localhost:3000/?url=https://example.com&nwc_url=nostr%2Bwalletconnect%3A%2F%2F...&amount=1"
```

Response: `402 Payment Required`

```
WWW-Authenticate: L402 macaroon="<macaroon>", invoice="<bolt11>"
```

The `macaroon` encodes the upstream URL, payment hash, and a 1-hour expiry, signed with an HMAC. Save it — you'll need it in step 3.

### Step 2 — Pay the invoice

Pay the `bolt11` invoice using any Lightning wallet. After payment you receive a **preimage** (32-byte hex string).

### Step 3 — Make the authenticated request

```bash
curl -v -H "Authorization: L402 <macaroon>:<preimage>" "http://localhost:3000/?url=https://example.com&nwc_url=nostr%2Bwalletconnect%3A%2F%2F...&amount=1"
```

The proxy verifies the macaroon signature and that `SHA256(preimage) == paymentHash`, then forwards the request to the upstream URL embedded in the macaroon and streams the response back. The query params are ignored on authenticated requests.

## Notes

- The signing secret is generated randomly at startup, so macaroons are invalidated when the server restarts.
- Macaroons expire after **1 hour**.
- The `Authorization` header is stripped before forwarding to the upstream.
