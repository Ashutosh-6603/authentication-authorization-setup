import { store } from "../store";
import { clearAuth, setAccessToken } from "../store/authSlice/authSlice";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:5000";

interface ApiRequestOptions extends RequestInit {
  withAuth?: boolean;
  retryOnUnauthorized?: boolean;
}

interface ApiErrorPayload {
  message?: string;
}

interface RefreshPayload {
  accessToken?: string;
}

export class ApiError extends Error {
  public readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

let refreshPromise: Promise<string | null> | null = null;

function buildHeaders(headers?: HeadersInit): Headers {
  const requestHeaders = new Headers(headers);

  if (!requestHeaders.has("Content-Type")) {
    requestHeaders.set("Content-Type", "application/json");
  }

  return requestHeaders;
}

async function parsePayload(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type");

  if (!contentType?.includes("application/json")) {
    return null;
  }

  try {
    return await response.json();
  } catch {
    return null;
  }
}

async function request<T>(path: string, options: ApiRequestOptions = {}): Promise<T> {
  const {
    withAuth = true,
    retryOnUnauthorized = withAuth,
    headers,
    ...requestInit
  } = options;
  const requestHeaders = buildHeaders(headers);

  if (withAuth) {
    const token = store.getState().auth.accessToken;

    if (token) {
      requestHeaders.set("Authorization", `Bearer ${token}`);
    }
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...requestInit,
    headers: requestHeaders,
    credentials: "include",
  });

  if (response.status === 401 && retryOnUnauthorized) {
    const refreshedToken = await refreshAccessToken();

    if (refreshedToken) {
      return request<T>(path, {
        ...options,
        retryOnUnauthorized: false,
      });
    }
  }

  const payload = await parsePayload(response);

  if (!response.ok) {
    const errorMessage =
      (payload as ApiErrorPayload | null)?.message ?? "Request failed";

    throw new ApiError(response.status, errorMessage);
  }

  return payload as T;
}

async function performRefresh(): Promise<string | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
      method: "POST",
      headers: buildHeaders(),
      credentials: "include",
    });
    const payload = (await parsePayload(response)) as RefreshPayload | null;

    if (!response.ok || !payload?.accessToken) {
      store.dispatch(clearAuth());
      return null;
    }

    store.dispatch(setAccessToken(payload.accessToken));
    return payload.accessToken;
  } catch {
    store.dispatch(clearAuth());
    return null;
  }
}

export async function refreshAccessToken(): Promise<string | null> {
  if (!refreshPromise) {
    refreshPromise = performRefresh().finally(() => {
      refreshPromise = null;
    });
  }

  return refreshPromise;
}

export function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  return request<T>(path, {
    ...options,
    withAuth: true,
    retryOnUnauthorized: true,
  });
}

export function authFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  return request<T>(path, {
    ...options,
    withAuth: false,
    retryOnUnauthorized: false,
  });
}
