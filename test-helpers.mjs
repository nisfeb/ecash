// Shared helpers for tests that hit the ~zod mint over HTTP.
export const SHIP_URL = process.env.SHIP_URL || 'http://localhost:8080';
const COOKIE = process.env.URBAUTH_COOKIE || '';
export function hasAuth() { return !!COOKIE; }
export async function adminFetch(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (COOKIE) headers.cookie = COOKIE;
  return fetch(`${SHIP_URL}${path}`, { ...opts, headers });
}
