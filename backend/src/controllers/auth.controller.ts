import type { Request, Response } from "express";
import { userRepository } from "../repositories/user.repository.ts";
import { hashPassword } from "../utils/password.ts";

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
