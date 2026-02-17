import { apiFetch } from "../../lib/api";

export async function loginRequest(email: string, password: string) {
  return apiFetch("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function refreshRequest() {
  return apiFetch("/auth/refresh", {
    method: "POST",
  });
}

export async function registerRequest(email: string, password: string) {
  return apiFetch("/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}
