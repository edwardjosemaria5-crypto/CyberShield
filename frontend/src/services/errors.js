const GENERIC_HTTP_MESSAGE =
  /^Request failed with status code \d+$|^Network Error$|^timeout of \d+ms exceeded$/;

/**
 * Produce a controlled, user-safe error string from a failed API call.
 *
 * Only a string `detail` field returned by the backend is shown verbatim
 * (the backend already emits short safe messages for its known failure
 * modes). Structurally rich FastAPI validation detail (arrays), stack
 * traces, environment values and generic transport messages are never
 * surfaced; callers fall back to a controlled message instead.
 */
export function normalizeApiError(error, fallback = 'The scan service could not be reached.') {
  if (!error || typeof error !== 'object') return fallback;
  const detail = error?.response?.data?.detail;
  if (typeof detail === 'string' && detail.trim() && !/[\r\n]/.test(detail)) {
    return detail.trim();
  }
  const message = error?.message;
  if (
    typeof message === 'string' &&
    message.trim() &&
    !/[\r\n]/.test(message) &&
    !GENERIC_HTTP_MESSAGE.test(message.trim())
  ) {
    return message.trim();
  }
  return fallback;
}
