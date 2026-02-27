# Backend Revision Guide

This document captures all backend improvements identified during the code review.

Each revision includes:
- what should change,
- why the current implementation is risky or weak,
- `Old code` (current state),
- `New code` (proposed state).

---

## R-01 (High): Populate `permissions` in auth middleware

### Why this is not good
`requirePermission(...)` reads `req.permissions`, but `requireAuth(...)` never sets it. Permission-protected routes will fail with `401` even for valid users.

### Files
- `backend/src/middlewares/auth.middleware.ts`

### Old code
```ts
try {
  const token = authHeader.split(" ")[1];
  const payload = verifyAccessToken(token);

  req.userId = payload.userId;
  req.roles = payload.roles;

  next();
} catch {
  return res.status(401).json({ message: "Invalid Token" });
}
```

### New code
```ts
try {
  const token = authHeader.split(" ")[1];
  const payload = verifyAccessToken(token);

  req.userId = payload.userId;
  req.roles = payload.roles ?? [];
  req.permissions = payload.permissions ?? [];

  return next();
} catch {
  return res.status(401).json({ message: "Invalid token" });
}
```

---

## R-02 (High): Enforce refresh token expiry in DB lookup

### Why this is not good
Refresh lookup only checks `revoked = false`. Expired refresh tokens can still be used.

### Files
- `backend/src/repositories/user.repository.ts`

### Old code
```ts
async findRefreshToken(token: string): Promise<RefreshToken | null> {
  const result = await pool.query<RefreshToken>(
    `
      SELECT * FROM refresh_tokens
      WHERE token = $1 AND revoked = false
    `,
    [token],
  );

  return result.rows[0] ?? null;
}
```

### New code
```ts
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
}
```

---

## R-03 (High): Re-check user active status during refresh

### Why this is not good
Disabled users are blocked at login, but can still refresh and keep receiving access tokens.

### Files
- `backend/src/controllers/auth.controller.ts`
- `backend/src/repositories/user.repository.ts`

### Old code
```ts
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
  const permissions = await userRepository.getUserPermissions(stored.user_id);

  const accessToken = signAccessToken({
    userId: stored.user_id,
    roles,
    permissions,
  });

  res.json({ accessToken });
}
```

### New code
```ts
export async function refresh(req: Request, res: Response) {
  const token = req.cookies.refreshToken;
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const tokenHash = hashRefreshToken(token);
  const stored = await userRepository.findRefreshToken(tokenHash);
  if (!stored) {
    return res.status(401).json({ message: "Invalid refresh token" });
  }

  const user = await userRepository.findById(stored.user_id);
  if (!user || !user.is_active) {
    await userRepository.revokeRefreshToken(tokenHash);
    return res.status(401).json({ message: "Unauthorized" });
  }

  const roles = await userRepository.getUserRoles(user.id);
  const permissions = await userRepository.getUserPermissions(user.id);

  const accessToken = signAccessToken({
    userId: user.id,
    roles,
    permissions,
  });

  return res.json({ accessToken });
}
```

---

## R-04 (High): Make refresh cookie security environment-aware

### Why this is not good
Cookie `secure: false` is hardcoded. This is unsafe outside local HTTP development.

### Files
- `backend/src/controllers/auth.controller.ts`

### Old code
```ts
res.cookie("refreshToken", refreshToken, {
  httpOnly: true,
  sameSite: "strict",
  secure: false, // Set to true in production with HTTPS
  expires: expiresAt,
});
```

### New code
```ts
const isProduction = process.env.NODE_ENV === "production";

const refreshCookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? "none" : "lax",
  expires: expiresAt,
  path: "/auth",
} as const;

res.cookie("refreshToken", refreshToken, refreshCookieOptions);
```

---

## R-05 (High): Store refresh tokens hashed at rest

### Why this is not good
Raw refresh tokens are currently stored in DB. If DB leaks, sessions are immediately hijackable.

### Files
- `backend/src/utils/refreshToken.ts`
- `backend/src/repositories/user.repository.ts`
- `backend/src/controllers/auth.controller.ts`

### Old code
```ts
export function generateRefreshToken(): string {
  return crypto.randomBytes(64).toString("hex");
}
```

```ts
await userRepository.saveRefreshToken(user.id, refreshToken, expiresAt);
const stored = await userRepository.findRefreshToken(token);
await userRepository.revokeRefreshToken(token);
```

### New code
```ts
import crypto from "crypto";

export function generateRefreshToken(): string {
  return crypto.randomBytes(64).toString("hex");
}

export function hashRefreshToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}
```

```ts
const refreshToken = generateRefreshToken();
const refreshTokenHash = hashRefreshToken(refreshToken);

await userRepository.saveRefreshToken(user.id, refreshTokenHash, expiresAt);

const tokenHash = hashRefreshToken(token);
const stored = await userRepository.findRefreshToken(tokenHash);
await userRepository.revokeRefreshToken(tokenHash);
```

---

## R-06 (Medium): Use DB transaction for register + role assignment

### Why this is not good
User creation and role assignment are split across calls. Failures can leave partial state.

### Files
- `backend/src/repositories/user.repository.ts`
- `backend/src/controllers/auth.controller.ts`

### Old code
```ts
const passwordHash = await hashPassword(password);
const user = await userRepository.create(email, passwordHash);

await userRepository.assignRole(user.id, "user");
```

### New code
```ts
async createUserWithDefaultRole(
  email: string,
  passwordHash: string,
  roleName = "user",
): Promise<User> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const userResult = await client.query<User>(
      `
        INSERT INTO users (email, password_hash)
        VALUES ($1, $2)
        RETURNING *
      `,
      [email, passwordHash],
    );

    const roleResult = await client.query(
      `
        INSERT INTO user_roles (user_id, role_id)
        SELECT $1, id FROM roles WHERE name = $2
      `,
      [userResult.rows[0].id, roleName],
    );

    if (roleResult.rowCount !== 1) {
      throw new Error("Default role not found");
    }

    await client.query("COMMIT");
    return userResult.rows[0];
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
```

---

## R-07 (Medium): Guard against silent role assignment failure

### Why this is not good
`INSERT ... SELECT` for roles can return `0` rows silently if role name is missing.

### Files
- `backend/src/repositories/user.repository.ts`

### Old code
```ts
async assignRole(userId: string, roleName: string): Promise<void> {
  await pool.query(
    `
  INSERT INTO user_roles (user_id, role_id)
  SELECT $1, id FROM roles WHERE name = $2
  `,
    [userId, roleName],
  );
}
```

### New code
```ts
async assignRole(userId: string, roleName: string): Promise<void> {
  const result = await pool.query(
    `
      INSERT INTO user_roles (user_id, role_id)
      SELECT $1, id FROM roles WHERE name = $2
    `,
    [userId, roleName],
  );

  if (result.rowCount !== 1) {
    throw new Error(`Role '${roleName}' not found`);
  }
}
```

---

## R-08 (Medium): Add robust backend request validation

### Why this is not good
Current validation only checks missing fields. Invalid formats and weak payloads pass through.

### Files
- `backend/src/controllers/auth.controller.ts`
- `backend/src/validators/auth.validator.ts` (new)

### Old code
```ts
const { email, password } = req.body;

if (!email || !password) {
  return res.status(400).json({
    message: "Email and password required",
  });
}
```

### New code
```ts
import { z } from "zod";

export const loginSchema = z.object({
  email: z.string().email().transform((v) => v.trim().toLowerCase()),
  password: z.string().min(8).max(128),
});

export const registerSchema = z.object({
  email: z.string().email().transform((v) => v.trim().toLowerCase()),
  password: z
    .string()
    .min(8)
    .max(128)
    .regex(/[A-Z]/, "Must contain uppercase")
    .regex(/[a-z]/, "Must contain lowercase")
    .regex(/\d/, "Must contain number"),
});
```

```ts
const parsed = loginSchema.safeParse(req.body);
if (!parsed.success) {
  return res.status(400).json({ message: "Invalid payload" });
}

const { email, password } = parsed.data;
```

---

## R-09 (Medium): Add security middleware and rate limiting

### Why this is not good
No request throttling or hardening headers on auth endpoints. Brute-force risk is higher.

### Files
- `backend/src/index.ts`

### Old code
```ts
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  }),
);
app.use(express.json());
app.use(cookieParser());
```

### New code
```ts
import helmet from "helmet";
import rateLimit from "express-rate-limit";

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(helmet());
app.use(express.json({ limit: "16kb" }));
app.use(cookieParser());
app.use("/auth/login", authLimiter);
app.use("/auth/refresh", authLimiter);
```

---

## R-10 (Medium): Fail fast if JWT secret is missing

### Why this is not good
`as string` hides misconfiguration. App should crash at startup if `JWT_SECRET` is absent.

### Files
- `backend/src/utils/jwt.ts`

### Old code
```ts
const JWT_SECRET = process.env.JWT_SECRET as string;
```

### New code
```ts
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is required");
}
```

---

## R-11 (Medium): Clear refresh cookie with matching options

### Why this is not good
Clearing without matching cookie attributes can fail in some browsers/proxies.

### Files
- `backend/src/controllers/auth.controller.ts`

### Old code
```ts
res.clearCookie("refreshToken");
res.json({ message: "Logged out" });
```

### New code
```ts
res.clearCookie("refreshToken", {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? "none" : "lax",
  path: "/auth",
});

return res.json({ message: "Logged out" });
```

---

## R-12 (Medium): Move CORS origin to env and guard debug route

### Why this is not good
Hardcoded origin blocks environment scaling. `/db-test` should not be publicly available in production.

### Files
- `backend/src/index.ts`

### Old code
```ts
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  }),
);

app.get("/db-test", async (_req, res) => {
  const result = await pool.query("SELECT NOW()");
  res.json(result.rows[0]);
});
```

### New code
```ts
const allowedOrigins = (process.env.CORS_ORIGINS ?? "http://localhost:5173")
  .split(",")
  .map((o) => o.trim());

app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
  }),
);

if (process.env.NODE_ENV !== "production") {
  app.get("/db-test", async (_req, res) => {
    const result = await pool.query("SELECT NOW()");
    return res.json(result.rows[0]);
  });
}
```

---

## R-13 (Low): Remove unused imports

### Why this is not good
Dead imports increase noise and make maintenance harder.

### Files
- `backend/src/index.ts`
- `backend/src/middlewares/role.middleware.ts`

### Old code
```ts
import { userRepository } from "./repositories/user.repository.ts";
import { requireAuth } from "./middlewares/auth.middleware.ts";
```

```ts
import { userRepository } from "../repositories/user.repository.ts";
```

### New code
```ts
// Remove unused imports from index.ts and role.middleware.ts
```

---

## R-14 (Low): Add production and CI scripts

### Why this is not good
Backend currently has only a dev script. Build/start/typecheck/lint scripts are needed for reliable CI/CD.

### Files
- `backend/package.json`

### Old code
```json
"scripts": {
  "dev": "nodemon --exec ts-node src/index.ts"
}
```

### New code
```json
"scripts": {
  "dev": "nodemon --exec ts-node src/index.ts",
  "typecheck": "tsc -p tsconfig.json --noEmit",
  "build": "tsc -p tsconfig.build.json",
  "start": "node dist/index.js",
  "lint": "eslint ."
}
```

---

## R-15 (Low): Improve secret management and env hygiene

### Why this is not good
Weak default-looking secrets and DB creds can be accidentally reused outside local development.

### Files
- `backend/.env`
- `backend/.env.example` (new recommended)

### Old code
```env
DB_PASSWORD=auth_password
JWT_SECRET=super_secret_jwt_key_change_later
```

### New code
```env
# backend/.env.example
PORT=5000
NODE_ENV=development

DB_HOST=localhost
DB_PORT=5432
DB_NAME=auth_db
DB_USER=auth_user
DB_PASSWORD=change_me

JWT_SECRET=replace_with_a_long_random_secret
CORS_ORIGINS=http://localhost:5173
```

---

## Suggested implementation order

1. R-01 to R-05 (auth correctness and token security first).
2. R-06 to R-12 (reliability and deployability).
3. R-13 to R-15 (cleanup and operational quality).

This order minimizes security risk first, then improves stability and maintainability.
