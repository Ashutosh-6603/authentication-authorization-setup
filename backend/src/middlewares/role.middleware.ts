import type { Response, NextFunction } from "express";

import { AuthRequest } from "./auth.middleware.ts";
import { userRepository } from "../repositories/user.repository.ts";

export function requireRole(...allowedRoles: string[]) {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    const roles = req.roles;

    if (!roles) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const hasAccess = roles.some((role) => allowedRoles.includes(role));

    if (!hasAccess) {
      return res.status(403).json({ message: "Forbidden" });
    }

    next();
  };
}
