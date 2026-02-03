import crypto from "crypto";

export function generateRefreshToken(): string {
  return crypto.randomBytes(64).toString("hex");
}
