import type { Request, Response, NextFunction } from "express";
import { verifyAccessToken } from "../utils/jwt.ts";

export interface AuthRequest extends Request {
  userId?: string;
  roles?: string[];
}

export function requireAuth(
  req: AuthRequest,
  res: Response,
  next: NextFunction,
) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const token = authHeader.split(" ")[1];
    const payload = verifyAccessToken(token);

    req.userId = payload.userId;
    req.roles = payload.roles;

    next();
  } catch {
    return res.status(401).json({ message: "Invalid Token" });
  }
}
