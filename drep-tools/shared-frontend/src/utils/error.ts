/**
 * Error envelope returned by both binaries on every 4xx/5xx response.
 * The `code` is a stable string discriminator (e.g. `"not_paired"`)
 * that the frontend dispatches on; `message` is human-readable.
 *
 * The generic parameter lets callers narrow `code` to a union literal
 * (e.g. `extractError<ErrorCode>(r)` in online-tool) for typed checks.
 */
export interface ErrorEnvelope<C extends string = string> {
  code: C
  message: string
}

/**
 * Read a structured error envelope from a fetch Response. Falls back to
 * a synthesised envelope using the body text + a generic code when the
 * server returned plain text (or any non-JSON 4xx/5xx).
 */
export async function extractError<C extends string = string>(
  r: Response,
): Promise<ErrorEnvelope<C>> {
  let text = ""
  try {
    text = await r.text()
  } catch {
    text = ""
  }
  if (text) {
    try {
      const parsed = JSON.parse(text)
      if (
        parsed
        && typeof parsed === "object"
        && typeof parsed.code === "string"
        && typeof parsed.message === "string"
      ) {
        return parsed as ErrorEnvelope<C>
      }
    } catch {
      /* fall through */
    }
  }
  return {
    code: "internal" as C,
    message: text.trim() || `HTTP ${r.status}`,
  }
}
