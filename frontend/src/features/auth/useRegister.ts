import { useMutation } from "@tanstack/react-query";
import { useAppDispatch } from "../../store/hooks";
import { loginRequest, registerRequest } from "./api";
import { setAccessToken } from "../../store/authSlice/authSlice";

export function useRegister() {
  const dispatch = useAppDispatch();

  return useMutation({
    mutationFn: async ({
      email,
      password,
    }: {
      email: string;
      password: string;
    }) => {
      await registerRequest(email, password);

      return loginRequest(email, password);
    },

    onSuccess: (data) => {
      dispatch(setAccessToken(data.accessToken));
    },
  });
}
