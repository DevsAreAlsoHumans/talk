let csrfToken = null;
let csrfRequest = null;

export class ApiError extends Error {
  constructor(status, code, message, details = []) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function setCsrfToken(token) {
  if (typeof token === "string" && token.length > 0) {
    csrfToken = token;
  }
}

export async function refreshCsrf() {
  if (csrfRequest) {
    return csrfRequest;
  }
  csrfRequest = fetch("/api/auth/csrf", {
    method: "GET",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  })
    .then(async (response) => {
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new ApiError(
          response.status,
          payload.error?.code || "csrf_error",
          payload.error?.message || "Impossible d'initialiser la protection CSRF",
        );
      }
      setCsrfToken(payload.csrf_token);
      return payload.csrf_token;
    })
    .finally(() => {
      csrfRequest = null;
    });
  return csrfRequest;
}

function isMutation(method) {
  return ["POST", "PUT", "PATCH", "DELETE"].includes(method.toUpperCase());
}

async function parsePayload(response) {
  if (response.status === 204) {
    return null;
  }
  return response.json().catch(() => ({}));
}

export async function apiFetch(path, options = {}, retryCsrf = true) {
  const method = (options.method || "GET").toUpperCase();
  const mutating = isMutation(method);
  if (mutating && !csrfToken) {
    await refreshCsrf();
  }

  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");
  if (options.body !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  if (mutating && csrfToken) {
    headers.set("X-CSRF-Token", csrfToken);
  }

  const response = await fetch(path, {
    ...options,
    method,
    headers,
    credentials: "same-origin",
  });
  const payload = await parsePayload(response);
  if (response.ok) {
    if (payload?.csrf_token) {
      setCsrfToken(payload.csrf_token);
    }
    return payload;
  }

  if (mutating && retryCsrf && response.status === 403) {
    csrfToken = null;
    await refreshCsrf();
    return apiFetch(path, options, false);
  }

  throw new ApiError(
    response.status,
    payload?.error?.code || "request_failed",
    payload?.error?.message || "La requête a échoué",
    payload?.details || [],
  );
}

export function jsonBody(value) {
  return JSON.stringify(value);
}
