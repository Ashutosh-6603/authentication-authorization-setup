import type { ReactElement } from "react";
import { Navigate } from "react-router-dom";
import { useAppSelector } from "../store/hooks";

interface PublicRouteProps {
  children: ReactElement;
}

export function PublicRoute({ children }: PublicRouteProps) {
  const { accessToken, isAuthInitialized } = useAppSelector(
    (state) => state.auth,
  );

  if (!isAuthInitialized) {
    return null;
  }

  if (accessToken) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
}
