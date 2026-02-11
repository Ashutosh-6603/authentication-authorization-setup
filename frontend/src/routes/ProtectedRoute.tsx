import type { JSX } from "react";
import { useAppSelector } from "../store/hooks";
import { Navigate } from "react-router-dom";

export function ProtectedRoute({ children }: { children: JSX.Element }) {
  const token = useAppSelector((state) => state.auth.accessToken);

  if (!token) {
    return <Navigate to="/login" />;
  }

  return children;
}
