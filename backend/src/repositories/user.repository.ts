import { pool } from "../db.ts";
import type { RefreshToken } from "../types/refresh-token.ts";
import type { User } from "../types/user.ts";

export const userRepository = {
  async findByEmail(email: string): Promise<User | null> {
    const result = await pool.query<User>(
      `SELECT * FROM users WHERE email = $1`,
      [email],
    );

    return result.rows[0] ?? null;
  },

  async findById(userId: string): Promise<User | null> {
    const result = await pool.query<User>(`SELECT * FROM users WHERE id = $1`, [
      userId,
    ]);

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

  async saveRefreshToken(
    userId: string,
    token: string,
    expiresAt: Date,
  ): Promise<void> {
    await pool.query(
      `
        INSERT INTO refresh_tokens (user_id, token, expires_at)
        VALUES ($1, $2, $3)
      `,
      [userId, token, expiresAt],
    );
  },

  async findRefreshToken(tokenHash: string): Promise<RefreshToken | null> {
    const result = await pool.query<RefreshToken>(
      `
        SELECT * 
        FROM refresh_tokens
        WHERE token_hash = $1 
          AND revoked = false 
          AND expires_at > NOW() 
        LIMIT 1
      `,
      [tokenHash],
    );

    return result.rows[0] ?? null;
  },

  async revokeRefreshToken(token: string) {
    await pool.query(
      `
        UPDATE refresh_tokens SET revoked = true WHERE token = $1
      `,
      [token],
    );
  },

  async getUserRoles(userId: string): Promise<string[]> {
    const result = await pool.query<{ name: string }>(
      `
        SELECT r.name
        FROM roles r
        JOIN user_roles ur ON ur.role_id = r.id
        WHERE ur.user_id = $1
      `,
      [userId],
    );

    return result.rows.map((r) => r.name);
  },

  async getUserPermissions(userId: string): Promise<string[]> {
    const result = await pool.query<{ name: string }>(
      `
        SELECT DISTINCT p.name
        FROM permissions p
        JOIN role_permissions rp ON rp.permission_id = p.id
        JOIN user_roles ur ON ur.role_id = rp.role_id
        WHERE ur.user_id = $1
      `,
      [userId],
    );

    return result.rows.map((r) => r.name);
  },
};
