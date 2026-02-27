import { useForm } from "react-hook-form";
import { useRegister } from "../features/auth/useRegister";
import { yupResolver } from "@hookform/resolvers/yup";
import { registerSchema } from "../features/auth/registerSchema";
import { ApiError } from "../lib/api";
import { Link, useNavigate } from "react-router-dom";

interface RegisterFormInputs {
  email: string;
  password: string;
  confirmPassword: string;
}

export default function Register() {
  const { mutate, isPending, isError, error } = useRegister();
  const navigate = useNavigate();

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<RegisterFormInputs>({
    resolver: yupResolver(registerSchema),
  });

  function onSubmit(data: RegisterFormInputs) {
    mutate({
      email: data.email,
      password: data.password,
    }, {
      onSuccess: () => {
        navigate("/dashboard", { replace: true });
      },
    });
  }

  const errorMessage =
    error instanceof ApiError ? error.message : "Registration failed";

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <form
        onSubmit={handleSubmit(onSubmit)}
        className="bg-white p-6 rounded-lg shadow-md w-80"
      >
        <h2 className="text-xl font-semibold mb-4 text-center">Register</h2>

        <input
          {...register("email")}
          placeholder="Email"
          className="w-full mb-1 px-3 py-2 border rounded"
        />
        {errors.email && (
          <p className="text-red-500 text-sm mb-2">{errors.email.message}</p>
        )}

        <input
          type="password"
          {...register("password")}
          placeholder="Password"
          className="w-full mb-1 px-3 py-2 border rounded"
        />
        {errors.password && (
          <p className="text-red-500 text-sm mb-2">{errors.password.message}</p>
        )}

        <input
          type="password"
          {...register("confirmPassword")}
          placeholder="Confirm Password"
          className="w-full mb-1 px-3 py-2 border rounded"
        />
        {errors.confirmPassword && (
          <p className="text-red-500 text-sm mb-3">
            {errors.confirmPassword.message}
          </p>
        )}

        <button
          type="submit"
          disabled={isPending}
          className="w-full bg-green-600 text-white py-2 rounded hover:bg-green-700 disabled:opacity-50"
        >
          {isPending ? "Registering..." : "Register"}
        </button>

        {isError && (
          <p className="text-red-500 mt-3 text-sm text-center">{errorMessage}</p>
        )}

        <p className="mt-3 text-sm text-center text-gray-600">
          Already have an account?{" "}
          <Link className="text-blue-600 hover:underline" to="/login">
            Login
          </Link>
        </p>
      </form>
    </div>
  );
}
