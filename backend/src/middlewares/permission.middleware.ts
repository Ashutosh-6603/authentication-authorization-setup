import type { Response, NextFunction } from "express";

import { AuthRequest } from "./auth.middleware.ts";

export function requirePermission(...allowed: string[]) {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    const permissions = req.permissions;

    if (!permissions) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const hasPermission = permissions.some((p) => allowed.includes(p));

    if (!hasPermission) {
      return res.status(403).json({ message: "Forbidden" });
    }

    next();
  };
}
