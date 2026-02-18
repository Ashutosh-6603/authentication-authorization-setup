import { createSlice, type PayloadAction } from "@reduxjs/toolkit";

interface AuthState {
  accessToken: string | null;
  isAuthInitialized: boolean;
}

const initialState: AuthState = {
  accessToken: null,
  isAuthInitialized: false,
};

const authSlice = createSlice({
  name: "auth",
  initialState,
  reducers: {
    setAccessToken(state, action: PayloadAction<string>) {
      state.accessToken = action.payload;
      state.isAuthInitialized = true;
    },
    clearAuth(state) {
      state.accessToken = null;
      state.isAuthInitialized = true;
    },
    setAuthInitialized(state) {
      state.isAuthInitialized = true;
    },
  },
});

export const { setAccessToken, clearAuth, setAuthInitialized } =
  authSlice.actions;
export default authSlice.reducer;
