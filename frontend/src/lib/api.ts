import { refreshRequest } from "../features/auth/api";
import { store } from "../store";
import { clearAuth, setAccessToken } from "../store/authSlice/authSlice";

const BASE_URL = "http://localhost:5000";

let isRefreshing = false;

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

  if (res.status === 401 && !isRefreshing) {
    try {
      isRefreshing = true;

      const refreshData = await refreshRequest();
      store.dispatch(setAccessToken(refreshData.accessToken));

      isRefreshing = false;

      // Retry the original request with the new token
      return apiFetch(path, options);
    } catch {
      store.dispatch(clearAuth());
      isRefreshing = false;
      throw new Error("Unauthorized");
    }
  }

  if (!res.ok) {
    throw new Error("Request failed");
  }

  return res.json();
}
