import { useMutation } from "@tanstack/react-query";
import { useAppDispatch } from "../../store/hooks";
import { loginRequest } from "./api";
import { setAccessToken } from "../../store/authSlice/authSlice";

export function useLogin() {
  const dispatch = useAppDispatch();

  return useMutation({
    mutationFn: ({ email, password }: { email: string; password: string }) =>
      loginRequest(email, password),
    onSuccess: (data) => {
      dispatch(setAccessToken(data.accessToken));
    },
  });
}
