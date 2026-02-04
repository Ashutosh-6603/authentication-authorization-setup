import type { Request, Response } from "express";
import bcrypt from "bcrypt";

import { userRepository } from "../repositories/user.repository.ts";
import { hashPassword } from "../utils/password.ts";
import { signAccessToken } from "../utils/jwt.ts";
import { generateRefreshToken } from "../utils/refreshToken.ts";

export async function register(req: Request, res: Response) {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      message: "Email and password are required",
    });
  }

  const existingUser = await userRepository.findByEmail(email);

  if (existingUser) {
    return res.status(409).json({
      message: "User already exists",
    });
  }

  const passwordHash = await hashPassword(password);
  const user = await userRepository.create(email, passwordHash);

  await userRepository.assignRole(user.id, "user");

  res.status(201).json({
    id: user.id,
    email: user.email,
    created_at: user.created_at,
  });
}

export async function login(req: Request, res: Response) {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      message: "Email and password required",
    });
  }

  const user = await userRepository.findByEmail(email);

  if (!user || !user.is_active) {
    return res.status(401).json({
      message: "Invalid credentials",
    });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password_hash);

  if (!isPasswordValid) {
    return res.status(401).json({
      message: "Invalid credentials",
    });
  }

  const roles = await userRepository.getUserRoles(user.id);

  // Create access token
  const accessToken = signAccessToken({ userId: user.id, roles });

  // Create refresh token
  const refreshToken = generateRefreshToken();

  const expiresAt = new Date(
    Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days
  );

  // Store refresh token in DB
  await userRepository.saveRefreshToken(user.id, refreshToken, expiresAt);

  // Send refresh token as HttpOnly cookie
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    sameSite: "strict",
    secure: false, // Set to true in production with HTTPS
    expires: expiresAt,
  });

  // Send access token in response
  res.json({
    accessToken,
  });
}

export async function refresh(req: Request, res: Response) {
  const token = req.cookies.refreshToken;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const stored = await userRepository.findRefreshToken(token);

  if (!stored) {
    return res.status(401).json({ message: "Invalid refresh token" });
  }

  const roles = await userRepository.getUserRoles(stored.user_id);

  const accessToken = signAccessToken({ userId: stored.user_id, roles });

  res.json({ accessToken });
}

export async function logout(req: Request, res: Response) {
  const token = req.cookies.refreshToken;

  if (token) {
    await userRepository.revokeRefreshToken(token);
  }

  res.clearCookie("refreshToken");
  res.json({ message: "Logged out" });
}
