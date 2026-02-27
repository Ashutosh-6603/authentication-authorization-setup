import { useLogin } from "../features/auth/useLogin";
import { useForm } from "react-hook-form";
import { yupResolver } from "@hookform/resolvers/yup";
import { loginSchema } from "../features/auth/loginSchema";
import { ApiError } from "../lib/api";
import { Link, useNavigate } from "react-router-dom";

interface LoginFormInputs {
  email: string;
  password: string;
}

export function Login() {
  const { mutate, isPending, isError, error } = useLogin();
  const navigate = useNavigate();

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormInputs>({
    resolver: yupResolver(loginSchema),
  });

  function onSubmit(data: LoginFormInputs) {
    mutate(data, {
      onSuccess: () => {
        navigate("/dashboard", { replace: true });
      },
    });
  }

  const errorMessage =
    error instanceof ApiError ? error.message : "Invalid credentials";

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <form
        onSubmit={handleSubmit(onSubmit)}
        className="bg-white p-6 rounded-lg shadow-md w-80"
      >
        <h2 className="text-xl font-semibold mb-4 text-center">Login</h2>

        {/* Email */}
        <input
          {...register("email")}
          placeholder="Email"
          className="w-full mb-1 px-3 py-2 border rounded"
        />

        {errors.email && (
          <p className="text-red-500 text-sm mb-2">{errors.email.message}</p>
        )}

        {/* Password */}
        <input
          type="password"
          {...register("password")}
          placeholder="Password"
          className="w-full mb-1 px-3 py-2 border rounded"
        />

        {errors.password && (
          <p className="text-red-500 text-sm mb-3">{errors.password.message}</p>
        )}

        <button
          type="submit"
          disabled={isPending}
          className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50"
        >
          {isPending ? "Logging in..." : "Login"}
        </button>

        {isError && (
          <p className="text-red-500 mt-3 text-sm text-center">{errorMessage}</p>
        )}

        <p className="mt-3 text-sm text-center text-gray-600">
          Don&apos;t have an account?{" "}
          <Link className="text-blue-600 hover:underline" to="/register">
            Register
          </Link>
        </p>
      </form>
    </div>
  );
}
