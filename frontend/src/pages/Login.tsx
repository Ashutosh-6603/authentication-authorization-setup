import { useState, type ChangeEvent, type FormEvent } from "react";
import { useLogin } from "../features/auth/useLogin";

export function Login() {
  const { mutate, isPending, isError } = useLogin();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  function handleSubmit(e: ChangeEvent<HTMLFormElement>) {
    e.preventDefault();

    mutate({ email, password });
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <form
        onSubmit={handleSubmit}
        className="text-xl font-semibold mb-4 text-center"
      >
        <h2 className="text-xl font-semibold mb-4 text-center">Login</h2>

        <input
          className="w-full mb-3 px-3 py-2 border rounded"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />

        <input
          className="w-full mb-4 px-3 py-2 border rounded"
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <button className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700">
          {isPending ? "Logging in..." : "Login"}
        </button>

        {isError && <p className="text-red-500 mt-2 text-sm">Login failed</p>}
      </form>
    </div>
  );
}
