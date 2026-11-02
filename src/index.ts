import Fastify from "fastify";
import cors from "@fastify/cors";
import { handleL402 } from "./l402.js";
import { handleX402 } from "./x402.js";
import { handleMPP } from "./mpp.js";
import { handleMPPDiscovery } from "./mpp-discovery.js";

const PORT = parseInt(process.env.PORT ?? "3000", 10);

// trustProxy: fly.io terminates TLS, so the public protocol/host come from
// X-Forwarded-* (needed for the x402 request binding, which covers the URL).
const app = Fastify({ logger: true, trustProxy: true });

await app.register(cors, {
  origin: true,
  exposedHeaders: ["WWW-Authenticate", "PAYMENT-REQUIRED", "PAYMENT-RESPONSE", "Payment-Receipt"],
});

// Keep every body as raw bytes: it is forwarded upstream as-is, and x402
// binds the exact body bytes in the request hash.
app.removeAllContentTypeParsers();
app.addContentTypeParser("*", { parseAs: "buffer" }, (_req, body, done) =>
  done(null, body),
);

app.all("/l402", handleL402);
app.all("/x402", handleX402);
app.all("/mpp", handleMPP);
app.get("/openapi.json", handleMPPDiscovery);

// --- Start ---

const shutdown = async () => {
  await app.close();
  process.exit(0);
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

await app.listen({ port: PORT, host: "0.0.0.0" });
