import { useEffect } from "react";
import { Login } from "./pages/Login";
import { useAppDispatch } from "./store/hooks";
import { refreshRequest } from "./features/auth/api";
import { clearAuth, setAccessToken } from "./store/authSlice/authSlice";

function App() {
  const dispatch = useAppDispatch();

  useEffect(() => {
    async function tryRefresh() {
      try {
        const data = await refreshRequest();
        dispatch(setAccessToken(data.accessToken));
      } catch (error) {
        dispatch(clearAuth());
      }
    }

    tryRefresh();
  }, [dispatch]);

  return (
    <>
      <Login />
    </>
  );
}

export default App;
