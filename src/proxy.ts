import type { FastifyRequest, FastifyReply } from "fastify";

export const HOP_BY_HOP_HEADERS = new Set([
  "host",
  "authorization",
  "connection",
  "transfer-encoding",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "upgrade",
]);

export async function proxyUpstream(
  request: FastifyRequest,
  upstreamUrl: string,
  reply: FastifyReply,
): Promise<Buffer> {
  const filteredHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(request.headers)) {
    if (!HOP_BY_HOP_HEADERS.has(k.toLowerCase()) && typeof v === "string") {
      filteredHeaders[k] = v;
    }
  }

  const hasBody =
    request.method !== "GET" &&
    request.method !== "HEAD" &&
    request.body != null &&
    (request.body as Buffer).length > 0;

  const upstreamRes = await fetch(upstreamUrl, {
    method: request.method,
    // Force uncompressed upstream response — the proxy buffers and re-sends
    // the body, so if the upstream returns a compressed encoding the browser
    // will never see the content-encoding header (we strip it below) and
    // will render raw binary.
    headers: { ...filteredHeaders, "accept-encoding": "identity" },
    body: hasBody ? new Uint8Array(request.body as Buffer) : undefined,
  });

  request.log.info(
    { url: upstreamUrl, status: upstreamRes.status },
    "Upstream responded",
  );

  reply.status(upstreamRes.status);
  for (const [k, v] of upstreamRes.headers) {
    // Skip these headers — we buffer and re-send the body, so:
    // - content-length: Fastify recomputes it from the buffer
    // - transfer-encoding: would conflict with the new content-length
    // - content-encoding: upstream is forced to identity encoding (see above)
    if (
      k === "transfer-encoding" ||
      k === "content-length" ||
      k === "content-encoding"
    )
      continue;
    reply.header(k, v);
  }

  return Buffer.from(await upstreamRes.arrayBuffer());
}
