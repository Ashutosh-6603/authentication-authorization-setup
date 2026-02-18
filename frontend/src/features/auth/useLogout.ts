import { useMutation } from "@tanstack/react-query";
import { clearAuth } from "../../store/authSlice/authSlice";
import { useAppDispatch } from "../../store/hooks";
import { logoutRequest } from "./api";

export function useLogout() {
  const dispatch = useAppDispatch();

  return useMutation({
    mutationFn: logoutRequest,
    onSuccess: () => {
      dispatch(clearAuth());
    },
  });
}
