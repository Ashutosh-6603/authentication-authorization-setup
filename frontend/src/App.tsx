import { useEffect } from "react";
import { Login } from "./pages/Login";
import { useAppDispatch } from "./store/hooks";
import { refreshRequest } from "./features/auth/api";
import {
  clearAuth,
  setAccessToken,
  setAuthInitialized,
} from "./store/authSlice/authSlice";
import Register from "./pages/Register";
import {
  BrowserRouter as Router,
  Navigate,
  Route,
  Routes,
} from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import { ProtectedRoute } from "./routes/ProtectedRoute";
import { PublicRoute } from "./routes/PublicRoute";

function App() {
  const dispatch = useAppDispatch();

  useEffect(() => {
    let isMounted = true;

    async function initializeAuth() {
      try {
        const data = await refreshRequest();

        if (isMounted) {
          dispatch(setAccessToken(data.accessToken));
        }
      } catch {
        if (isMounted) {
          dispatch(clearAuth());
        }
      } finally {
        if (isMounted) {
          dispatch(setAuthInitialized());
        }
      }
    }

    initializeAuth();

    return () => {
      isMounted = false;
    };
  }, [dispatch]);

  return (
    <Router>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />

        <Route
          path="/login"
          element={
            <PublicRoute>
              <Login />
            </PublicRoute>
          }
        />

        <Route
          path="/register"
          element={
            <PublicRoute>
              <Register />
            </PublicRoute>
          }
        />

        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />

        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Router>
  );
}

export default App;
