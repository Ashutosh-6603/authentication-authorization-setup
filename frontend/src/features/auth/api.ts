import { authFetch, refreshAccessToken } from "../../lib/api";

export interface AccessTokenResponse {
  accessToken: string;
}

export interface RegisterResponse {
  id: string;
  email: string;
  created_at: string;
}

export interface LogoutResponse {
  message: string;
}

export function loginRequest(
  email: string,
  password: string,
): Promise<AccessTokenResponse> {
  return authFetch<AccessTokenResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export function registerRequest(
  email: string,
  password: string,
): Promise<RegisterResponse> {
  return authFetch<RegisterResponse>("/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function refreshRequest(): Promise<AccessTokenResponse> {
  const accessToken = await refreshAccessToken();

  if (!accessToken) {
    throw new Error("Unable to refresh session");
  }

  return { accessToken };
}

export function logoutRequest(): Promise<LogoutResponse> {
  return authFetch<LogoutResponse>("/auth/logout", {
    method: "POST",
  });
}
