import Fastify from "fastify";
import cors from "@fastify/cors";
import { handleL402 } from "./l402.js";
import { handleX402 } from "./x402.js";

const PORT = parseInt(process.env.PORT ?? "3000", 10);

const app = Fastify({ logger: true });

await app.register(cors, {
  origin: true,
  exposedHeaders: ["WWW-Authenticate", "PAYMENT-REQUIRED", "PAYMENT-RESPONSE"],
});

app.addContentTypeParser("*", { parseAs: "buffer" }, (_req, body, done) =>
  done(null, body),
);

app.all("/l402", handleL402);
app.all("/x402", handleX402);

// --- Start ---

const shutdown = async () => {
  await app.close();
  process.exit(0);
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

await app.listen({ port: PORT, host: "0.0.0.0" });
