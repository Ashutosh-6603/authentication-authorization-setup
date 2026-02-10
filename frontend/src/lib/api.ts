import { store } from "../store";

const BASE_URL = "http://localhost:5000";

export async function apiFetch(path: string, options: RequestInit = {}) {
  const state = store.getState();
  const token = state.auth.accessToken;

  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token && { Authorization: `Bearer ${token}` }),
      ...options.headers,
    },
    credentials: "include",
  });

  if (!res.ok) {
    throw new Error("Request failed");
  }

  return res.json();
}
