import { useNavigate } from "react-router-dom";
import { useLogout } from "../features/auth/useLogout";
import { ApiError } from "../lib/api";

export default function Dashboard() {
  const navigate = useNavigate();
  const { mutate, isPending, isError, error } = useLogout();

  function handleLogout() {
    mutate(undefined, {
      onSuccess: () => {
        navigate("/login", { replace: true });
      },
    });
  }

  const errorMessage =
    error instanceof ApiError ? error.message : "Unable to log out";

  return (
    <div className="min-h-screen bg-gray-100 p-8">
      <div className="mx-auto max-w-5xl rounded-lg border border-dashed border-gray-300 bg-white p-8">
        <div className="flex items-center justify-between gap-4">
          <h1 className="text-2xl font-semibold text-gray-900">Dashboard</h1>
          <button
            type="button"
            className="rounded bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
            onClick={handleLogout}
            disabled={isPending}
          >
            {isPending ? "Logging out..." : "Logout"}
          </button>
        </div>

        {isError && <p className="mt-4 text-sm text-red-600">{errorMessage}</p>}
      </div>
    </div>
  );
}
