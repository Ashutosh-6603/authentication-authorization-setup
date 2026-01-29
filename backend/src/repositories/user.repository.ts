import { pool } from "../db.ts";
import type { User } from "../types/user.ts";

export const userRepository = {
  async findByEmail(email: string): Promise<User | null> {
    const result = await pool.query<User>(
      `SELECT * FROM users WHERE email = $1`,
      [email],
    );

    return result.rows[0] ?? null;
  },

  async create(email: string, passwordHash: string): Promise<User> {
    const result = await pool.query<User>(
      `
        INSERT INTO users (email, password_hash)
        VALUES ($1, $2)
        RETURNING *;
      `,
      [email, passwordHash],
    );

    return result.rows[0];
  },

  async assignRole(userId: string, roleName: string): Promise<void> {
    await pool.query(
      `
    INSERT INTO user_roles (user_id, role_id)
    SELECT $1, id FROM roles WHERE name = $2
    `,
      [userId, roleName],
    );
  },
};
