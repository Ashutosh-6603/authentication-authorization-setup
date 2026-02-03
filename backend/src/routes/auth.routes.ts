import { Router } from "express";
import {
  register,
  login,
  refresh,
  logout,
} from "../controllers/auth.controller.ts";

export const authRouter = Router();

authRouter.post("/register", register);
authRouter.post("/login", login);
authRouter.post("/refresh", refresh);
authRouter.post("/logout", logout);
