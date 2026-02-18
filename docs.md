# Steps

## Backend Integration

## Step 1: Create backend project

- Create the initial structure:

```perl
auth-system/
 ├─ backend/
 └─ docker/
```

- Move into the `backend` folder and initialize:

```bash
cd backend
npm init -y
```

## Step 2: Install dependencies

- Run the following commands:

```bash
npm install express dotenv cors pg
npm install --save-dev nodemon
npm install -D typescript ts-node nodemon @types/node @types/express @types/cors
npm i --save-dev @types/pg
```

- Package overview:

| Package        | Why                          |
| -------------- | ---------------------------- |
| express        | REST API framework           |
| dotenv         | Environment variables        |
| cors           | Allow frontend access        |
| pg             | PostgreSQL client            |
| nodemon        | Auto-restart during dev      |
| typescript     | TypeScript compiler          |
| ts-node        | TypeScript execution         |
| @types/node    | TypeScript types for Node.js |
| @types/express | TypeScript types for Express |
| @types/cors    | TypeScript types for CORS    |

## Step 3: Configure TypeScript

- Initialize TypeScript:

```bash
npx tsc --init
```

- Update `backend/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "allowImportingTsExtensions": true,
    "noEmit": true
  }
}
```

## Step 4: Dev script

- Update `package.json`:

```json
{
  "type": "module",
  "scripts": {
    "dev": "nodemon --exec ts-node src/index.ts"
  }
}
```

## Step 5: Create a minimal server with Express

- Create `backend/src/index.ts`:

```ts
import express from "express";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```

- Note: The `/health` endpoint is mandatory for infra and monitoring.
- Run the dev server:

```bash
npm run dev
```

- Add a `.env` file in the `backend` folder:

```env
PORT=5000
```

- Create a `.gitignore` file in the `backend` folder:

```gitignore
node_modules
dist
.env
```

## Step 6: Set up PostgreSQL via Docker

- Create `docker/docker-compose.yml`:

```yaml
services:
  postgres:
    image: postgres:16
    container_name: auth_postgres
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: auth_db
      POSTGRES_USER: auth_user
      POSTGRES_PASSWORD: auth_password
    volumes:
      - auth_pgdata:/var/lib/postgresql/data

volumes: auth_pgdata
```

- Run the following commands:

```bash
cd docker

docker compose up -d
```

- Add the following to the `.env` file:

```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=auth_db
DB_USER=auth_user
DB_PASSWORD=auth_password
```

## Step 7: PostgreSQL connection

- Create the file `backend/src/db.ts`:

```ts
import dotenv from "dotenv";
dotenv.config();

import { Pool } from "pg";

export const pool = new Pool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
});
```

- Why: `Pool` is required for concurrency.

## Step 8: Database connectivity test

- Update `backend/src/index.ts`:

```ts
import { pool } from "./db.js";

app.get("/db-test", async (_req, res) => {
  const result = await pool.query("SELECT NOW()");
  res.json(result.rows[0]);
});
```

## Step 9: Set up authentication database schema (PostgreSQL)

- In DBeaver, open the SQL script for the `auth_db` database and run the queries below in order.
- Enable UUID support:

```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```

- Why:
  - UUIDs are safer than incremental IDs.
  - Better for distributed systems.
  - Avoids user enumeration.

- Create the `users` table:

```sql
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

- Why:
  - `email UNIQUE` -> login identity.
  - `password_hash` -> never store passwords.
  - `is_active` -> soft-disable users.
  - `created_at` -> auditing.

- Create the `roles` table:

```sql
CREATE TABLE roles (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);
```

- Why:
  - Roles change rarely.
  - `SERIAL` is fine here (internal use only).
  - Separate tables enable RBAC scaling.

- Seed roles:

```sql
INSERT INTO roles (name)
VALUES
  ('user'),
  ('admin'),
  ('super-admin');
```

- Why:
  - Fixed roles.
  - Enforced by the DB itself, not code enums.

- `user_roles` (many-to-many):

```sql
CREATE TABLE user_roles (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id INT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
```

- Why:
  - Users can have multiple roles.
  - `ON DELETE CASCADE` keeps data clean.
  - Composite PK prevents duplicates.

- Indexes (important, minimal):

```sql
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
```

- Why:
  - Login is email based.
  - Role lookup happens on every request.

## Step 10: Type-safe DB access layer (Users)

- Create DB types at `backend/src/types/user.ts`:

```ts
export interface User {
  id: string;
  email: string;
  password_hash: string;
  is_active: boolean;
  created_at: Date;
}
```

- Why:
  - Central source of truth.
  - Prevents "any"-driven bugs.
  - Mirrors the DB exactly (important).

- Create the users repository at `backend/src/repositories/user.repository.ts`:

```ts
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
      RETURNING *
      `,
      [email, passwordHash],
    );

    return result.rows[0];
  },
};
```

- Why:
  - Parameterized queries -> SQL injection safe.
  - Repository pattern -> business logic stays clean.
  - No framework dependencies.

- Temporary test endpoint (sanity only).
- Update `backend/src/index.ts`:

```ts
import { userRepository } from "./repositories/user.repository.ts";

app.post("/test-user", async (req, res) => {
  const { email } = req.body;

  const user = await userRepository.create(email, "dummy_password_hash");

  res.json(user);
});
```

- Test it in Postman.

## Step 11: User registration, password hashing, and validation

- Install required dependencies:

```bash
npm install bcrypt
npm install -D @types/bcrypt
```

- Why:
  - `bcrypt` is battle-tested.
  - Slow hashing -> brute-force resistant.

- Create the password hashing utility at `backend/src/utils/password.ts`:

```ts
import bcrypt from "bcrypt";

const SALT_ROUNDS = 12;

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}
```

- Why:
  - Centralized hashing logic.
  - Easy to tune cost factor later.

- Extend the user repository for role assignment.
- Update `backend/src/repositories/user.repository.ts`:

```ts
async assignRole(userId: string, roleName: string): Promise<void> {
  await pool.query(
    `
    INSERT INTO user_roles (user_id, role_id)
    SELECT $1, id FROM roles WHERE name = $2
    `,
    [userId, roleName]
  );
}
```

- Why:
  - DB decides role ID.
  - No hardcoded role numbers.
  - Safe and scalable.

- Create the user registration endpoint.
- Create the file `backend/src/controllers/auth.controller.ts`:

```ts
import { Request, Response } from "express";
import { userRepository } from "../repositories/user.repository.ts";
import { hashPassword } from "../utils/password.ts";

export async function register(req: Request, res: Response) {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password required" });
  }

  const existingUser = await userRepository.findByEmail(email);
  if (existingUser) {
    return res.status(409).json({ message: "User already exists" });
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
```

- Why:
  - Validation first.
  - Hash before DB insert.
  - Default role assignment is explicit.

- Create the auth routes file.
- Create the file `backend/src/routes/auth.routes.ts`:

```ts
import { Router } from "express";
import { register } from "../controllers/auth.controller.ts";

export const authRouter = Router();

authRouter.post("/register", register);
```

- Wire routes and remove the test endpoint.
- Update `backend/src/index.ts`:

```ts
import { authRouter } from "./routes/auth.routes.ts";

app.use("/auth", authRouter);
```

## Step 12: Login and JWT access token (Authentication core)

- Install the JWT dependencies:

```bash
npm install jsonwebtoken
npm install -D @types/jsonwebtoken
```

- Why:
  - Stateless auth.
  - Scales horizontally.
  - Industry standard for APIs.

- Create the JWT utility.
- Create the file `backend/src/utils/jwt.ts`:

```ts
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET!;
const JWT_EXPIRES_IN = "15m";

export interface JwtPayload {
  userId: string;
}

export function signAccessToken(payload: JwtPayload): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

export function verifyAccessToken(token: string): JwtPayload {
  return jwt.verify(token, JWT_SECRET) as JwtPayload;
}
```

- Why:
  - Centralized token logic.
  - Short expiry -> safer.
  - Typed payload.

- Add JWT secret to the `.env` file:

```env
JWT_SECRET=super_secret_jwt_key_change_later
```

- Why:
  - Never hardcode secrets.
  - Will rotate later.

- Create the login controller.
- Add the API to `backend/src/controllers/auth.controller.ts`:

```ts
import bcrypt from "bcrypt";
import { signAccessToken } from "../utils/jwt.ts";

export async function login(req: Request, res: Response) {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password required" });
  }

  const user = await userRepository.findByEmail(email);
  if (!user || !user.is_active) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password_hash);
  if (!isPasswordValid) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const accessToken = signAccessToken({ userId: user.id });

  res.json({ accessToken });
}
```

- Why:
  - Same error for wrong email/password (security).
  - Token contains only `userId`.
  - No routes yet (intentional).

- Add the login route to `backend/src/routes/auth.routes.ts`:

```ts
import { login } from "../controllers/auth.controller.ts";

authRouter.post("/login", login);
```

- Create the auth middleware.
- Create the file `backend/src/middlewares/auth.middleware.ts`:

```ts
import { Request, Response, NextFunction } from "express";
import { verifyAccessToken } from "../utils/jwt.ts";

export interface AuthRequest extends Request {
  userId?: string;
}

export function requireAuth(
  req: AuthRequest,
  res: Response,
  next: NextFunction,
) {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const token = authHeader.split(" ")[1];
    const payload = verifyAccessToken(token);
    req.userId = payload.userId;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}
```

- Why:
  - Backend-enforced auth.
  - Token verification per request.
  - Typed request extension.

- Test the protected route.
- Add this temporary route in `index.ts`:

```ts
import { requireAuth } from "./middlewares/auth.middleware.ts";

app.get("/protected", requireAuth, (req, res) => {
  res.json({ message: "You are authenticated" });
});
```

- Login:

```postman
POST /auth/login
{
  "email": "user1@example.com",
  "password": "User@1"
}
```

- Use the token in the protected route:

```postman
GET /protected
Authorization: Bearer <token>
```

## Step 13: Refresh tokens and logout (Session control)

- In DBeaver, create the `refresh_tokens` table:

```sql
CREATE TABLE refresh_tokens (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

```sql
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
```

- Why:
  - Enables logout and session invalidation.
  - Supports multiple devices later.
  - DB-backed security.

- Install the cookie support packages:

```bash
npm install cookie-parser
npm install -D @types/cookie-parser
```

- Wire the cookie parser into the `index.ts` file:

```ts
import cookieParser from "cookie-parser";

app.use(cookieParser());
```

- Why:
  - Read `HttpOnly` cookies safely.
  - Required for refresh flow.

- Create the file `backend/src/utils/refreshToken.ts`:

```ts
import crypto from "crypto";

export function generateRefreshToken(): string {
  return crypto.randomBytes(64).toString("hex");
}
```

- Why:
  - Not JWT.
  - Fully random.
  - Safer for long-lived tokens.

- Extend the user repository.
- Update the file `backend/src/repositories/user.repository.ts`:

```ts
async saveRefreshToken(userId:string, token:string, expiresAt:Date) {
  await pool.query(
    `
      INSERT INTO refresh_tokens (user_id, token, expires_at)
      VALUES ($1, $2, $3)
    `,
    [userId, token, expiresAt]
  );
}

async findRefreshToken (token:string) {
  const result = await pool.query(
    `
      SELECT * FROM refresh_tokens
      WHERE token = $1 AND revoked = false
    `,
    [token]
  );

  return result.rows[0] ?? null;
}

async revokeRefreshToken(token: string) {
  await pool.query(
    `
      UPDATE refresh_tokens SET revoked = true WHERE token = $1
    `,
    [token]
  );
}
```

- Why:
  - Explicit lifecycle control.
  - DB decides session validity.

- Issue refresh token on login.
- Update the login controller (`backend/src/controllers/auth.controller.ts`):

```ts
import { generateRefreshToken } from "../utils/refreshToken.ts";

// add the below code under the accessToken variable
const refreshToken = generateRefreshToken();
const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

await userRepository.saveRefreshToken(user.id, refreshToken, expiresAt);

res.cookie("refreshToken", refreshToken, {
  httpOnly: true,
  sameSite: "strict",
  secure: false, // true in production
  expires: expiresAt,
});

res.json({ accessToken });
```

- Why:
  - Refresh token never touches JS.
  - Cookie is CSRF-resistant (sameSite).
  - Expiry enforced by DB + browser.

- Refresh endpoint (`backend/src/controllers/auth.controller.ts`):

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

  const accessToken = signAccessToken({ userId: stored.user_id });
  res.json({ accessToken });
}
```

- You will get a type error after creating the `refresh` endpoint. Create the file `backend/src/types/refresh-token.ts`:

```ts
export interface RefreshToken {
  id: string;
  user_id: string;
  token: string;
  expires_at: Date;
  revoked: boolean;
  created_at: Date;
}
```

- Then update the `user.repository.ts` file:

```ts
import { RefreshToken } from "../types/refresh-token.ts";

async findRefreshToken(token: string): Promise<RefreshToken | null> {
  const result = await pool.query<RefreshToken>(
    `
    SELECT * FROM refresh_tokens
    WHERE token = $1 AND revoked = false
    `,
    [token]
  );

  return result.rows[0] ?? null;
}
```

- Now the auth controller should have no error in the refresh endpoint.

- Logout endpoint:

```ts
export async function logout(req: Request, res: Response) {
  const token = req.cookies.refreshToken;

  if (token) {
    await userRepository.revokeRefreshToken(token);
  }

  res.clearCookie("refreshToken");
  res.json({ message: "Logged out" });
}
```

- Add the routes (`backend/src/routes/auth.routes.ts`):

```ts
authRouter.post("/refresh", refresh);
authRouter.post("/logout", logout);
```

## Step 14: Role-based authorization (RBAC)

- Update repository (`backend/src/repositories/user.repository.ts`):

```ts
async getUserRoles(userId: string): Promise<string[]> {
  const result = await pool.query<{ name: string }>(
    `
    SELECT r.name
    FROM roles r
    JOIN user_roles ur ON ur.role_id = r.id
    WHERE ur.user_id = $1
    `,
    [userId]
  );

  return result.rows.map(r => r.name);
}
```

- Why:
  - DB is the source of truth.
  - Supports multiple roles per user.
  - Scales to permissions later.

- Extend Auth Request.
- Update auth middleware types (`backend/src/middlewares/auth.middleware.ts`):

```ts
export interface AuthRequest extends Request {
  userId?: string;
  roles?: string[];
}
```

- Role middleware.
- Create the file `backend/src/middlewares/role.middleware.ts`:

```ts
import { Response, NextFunction } from "express";
import { AuthRequest } from "./auth.middleware.ts";
import { userRepository } from "../repositories/user.repository.ts";

export function requireRole(...allowedRoles: string[]) {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const roles = await userRepository.getUserRoles(req.userId);
    req.roles = roles;

    const hasAccess = roles.some((role) => allowedRoles.includes(role));

    if (!hasAccess) {
      return res.status(403).json({ message: "Forbidden" });
    }

    next();
  };
}
```

- Why:
  - Variadic roles -> flexible.
  - Admin only.
  - Admin + super-admin.
  - Reusable everywhere.

## Step 15: Add roles to JWT (Performance optimization)

- Update JWT payload type (`backend/src/utils/jwt.ts`):

```ts
export interface JwtPayload {
  userId: string;
  roles: string[];
}
```

- Include roles when signing the token.
- Update the login controller:

```ts
const roles = await userRepository.getUserRoles(user.id);

const accessToken = signAccessToken({
  userId: user.id,
  roles,
});
```

- Why:
  - Roles snapshot at login.
  - Avoids DB hits per request.
  - Token is short-lived anyway.

- Update refresh endpoint (`auth.controller.ts`):

```ts
const stored = await userRepository.findRefreshToken(token);
if (!stored) {
  return res.status(401).json({ message: "Invalid refresh token" });
}

const roles = await userRepository.getUserRoles(stored.user_id);

const accessToken = signAccessToken({
  userId: stored.user_id,
  roles,
});

res.json({ accessToken });
```

- Why:
  - Role changes propagate on refresh.
  - DB still controls long-lived sessions.

- Update auth middleware (`backend/src/middlewares/auth.middleware.ts`):

```ts
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

  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const token = authHeader.split(" ")[1];
    const payload = verifyAccessToken(token);

    req.userId = payload.userId;
    req.roles = payload.roles;

    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}
```

- Simplify role middleware (no DB call) (`backend/src/middlewares/role.middleware.ts`):

```ts
export function requireRole(...allowedRoles: string[]) {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
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
```

- Why:
  - Zero DB access.
  - Extremely fast.
  - Clean separation of concerns.

## Step 16: Permission-Based Authorization (PBAC)

- Database Schema (permissions)

```sql
CREATE TABLE permissions (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE role_permissions (
  role_id INT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id INT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);
```

- Why:
  - Many-to-many relationship.
  - Roles stay stable
  - Permissions grow with features

- Seed base permissions

```sql
INSERT INTO permissions (name) VALUES
  ('todo:create'),
  ('todo:update'),
  ('todo:delete'),
  ('user:read'),
  ('user:ban');
```

- Why:
  - Permissions are verbs on resources.
  - Easy to reason about
  - Auditable

- Map permissions to roles

```sql
-- admin permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'admin'
AND p.name IN ('todo:create', 'todo:update', 'user:read');

-- super-admin gets everything
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'super-admin';
```

- Why"
  - DB is the source of truth
  - No permission logic in code

- Fetch permissions for a user (Repository method in `user.repository.ts`)

```ts
async getUserPermissions(userId: string): Promise<string[]> {
  const result = await pool.query<{ name: string }>(
    `
    SELECT DISTINCT p.name
    FROM permissions p
    JOIN role_permissions rp ON rp.permission_id = p.id
    JOIN user_roles ur ON ur.role_id = rp.role_id
    WHERE ur.user_id = $1
    `,
    [userId]
  );

  return result.rows.map(r => r.name);
}
```

- Why:
  - Derived permissions
  - Supports multi-role users
  - Future-proof

- Include permission in JWT (access token)

- Login & refresh (conceptual change only)

```ts
const permissions = await userRepository.getUserPermissions(user.id);

signAccessToken({
  userId: user.id,
  roles,
  permissions,
});
```

- Update JWT payload type (`backend/src/utils/jwt.ts`):

```ts
export interface JwtPayload {
  userId: string;
  roles: string[];
  permissions: string[];
}
```

- Why:
  - Zero DB hits per request
  - Permissions evaluated instantly
  - Refresh keeps them in sync

- Permission middleware (`backend/src/middlewares/permission.middleware.ts`):

```ts
import { Response, NextFunction } from "express";
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
```

- Example usage

```ts
app.post("/todos", requireAuth, requirePermission("todo:create"), createTodo);

app.delete("/users/:id", requireAuth, requirePermission("user:ban"), banUser);
```

## Frontend Integration

This section is the canonical frontend implementation guide for the backend authentication and authorization APIs in this project.

### Backend APIs used by frontend

| Method | Endpoint         | Purpose                                            |
| ------ | ---------------- | -------------------------------------------------- |
| `POST` | `/auth/register` | Register a new user                                |
| `POST` | `/auth/login`    | Login and get access token                         |
| `POST` | `/auth/refresh`  | Refresh access token using HttpOnly refresh cookie |
| `POST` | `/auth/logout`   | Revoke refresh token and logout                    |

### Frontend goals

- Keep authentication state predictable and centralized.
- Keep API logic reusable and typed.
- Support silent session restore on page refresh.
- Protect private routes and redirect users correctly.
- Provide clean login, register, and dashboard flows.

## Step 1: Install Frontend Dependencies

If you are setting this up from scratch, create the frontend app with Vite first:

```bash
npm create vite@latest frontend -- --template react-ts
```

Install required dependencies:

```bash
npm install react-router-dom @reduxjs/toolkit react-redux @tanstack/react-query react-hook-form yup @hookform/resolvers tailwindcss @tailwindcss/vite
```

Why these packages:

- `react-router-dom`: client-side routing.
- `@reduxjs/toolkit` + `react-redux`: auth state store.
- `@tanstack/react-query`: mutation/query orchestration.
- `react-hook-form` + `yup`: form state + validation.
- `tailwindcss`: UI styling.

## Step 2: Create Auth State with Redux Toolkit

Create `frontend/src/store/index.ts`:

```ts
import { configureStore } from "@reduxjs/toolkit";
import authReducer from "./authSlice/authSlice";

export const store = configureStore({
  reducer: {
    auth: authReducer,
  },
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
```

Create `frontend/src/store/authSlice/authSlice.ts`:

```ts
import { createSlice, type PayloadAction } from "@reduxjs/toolkit";

interface AuthState {
  accessToken: string | null;
  isAuthInitialized: boolean;
}

const initialState: AuthState = {
  accessToken: null,
  isAuthInitialized: false,
};

const authSlice = createSlice({
  name: "auth",
  initialState,
  reducers: {
    setAccessToken(state, action: PayloadAction<string>) {
      state.accessToken = action.payload;
      state.isAuthInitialized = true;
    },
    clearAuth(state) {
      state.accessToken = null;
      state.isAuthInitialized = true;
    },
    setAuthInitialized(state) {
      state.isAuthInitialized = true;
    },
  },
});

export const { setAccessToken, clearAuth, setAuthInitialized } =
  authSlice.actions;
export default authSlice.reducer;
```

Create typed hooks in `frontend/src/store/hooks.ts`:

```ts
import {
  useDispatch,
  useSelector,
  type TypedUseSelectorHook,
} from "react-redux";
import type { AppDispatch, RootState } from ".";

export const useAppDispatch = () => useDispatch<AppDispatch>();
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector;
```

Why `isAuthInitialized` exists:

- It prevents route flicker while silent refresh is running.
- Routes can wait until auth bootstrap completes.

## Step 3: Configure React Query and Providers

Create `frontend/src/lib/queryClient.ts`:

```ts
import { QueryClient } from "@tanstack/react-query";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});
```

Update `frontend/src/main.tsx`:

```tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.tsx";
import { Provider } from "react-redux";
import { store } from "./store/index.ts";
import { QueryClientProvider } from "@tanstack/react-query";
import { queryClient } from "./lib/queryClient.ts";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Provider store={store}>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </Provider>
  </StrictMode>,
);
```

## Step 4: Build a Typed API Layer with Refresh Handling

Create `frontend/src/lib/api.ts`:

```ts
import { store } from "../store";
import { clearAuth, setAccessToken } from "../store/authSlice/authSlice";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:5000";

interface ApiRequestOptions extends RequestInit {
  withAuth?: boolean;
  retryOnUnauthorized?: boolean;
}

interface ApiErrorPayload {
  message?: string;
}

interface RefreshPayload {
  accessToken?: string;
}

export class ApiError extends Error {
  public readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

let refreshPromise: Promise<string | null> | null = null;

function buildHeaders(headers?: HeadersInit): Headers {
  const requestHeaders = new Headers(headers);

  if (!requestHeaders.has("Content-Type")) {
    requestHeaders.set("Content-Type", "application/json");
  }

  return requestHeaders;
}

async function parsePayload(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type");

  if (!contentType?.includes("application/json")) {
    return null;
  }

  try {
    return await response.json();
  } catch {
    return null;
  }
}

async function request<T>(
  path: string,
  options: ApiRequestOptions = {},
): Promise<T> {
  const {
    withAuth = true,
    retryOnUnauthorized = withAuth,
    headers,
    ...requestInit
  } = options;
  const requestHeaders = buildHeaders(headers);

  if (withAuth) {
    const token = store.getState().auth.accessToken;

    if (token) {
      requestHeaders.set("Authorization", `Bearer ${token}`);
    }
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...requestInit,
    headers: requestHeaders,
    credentials: "include",
  });

  if (response.status === 401 && retryOnUnauthorized) {
    const refreshedToken = await refreshAccessToken();

    if (refreshedToken) {
      return request<T>(path, {
        ...options,
        retryOnUnauthorized: false,
      });
    }
  }

  const payload = await parsePayload(response);

  if (!response.ok) {
    const errorMessage =
      (payload as ApiErrorPayload | null)?.message ?? "Request failed";

    throw new ApiError(response.status, errorMessage);
  }

  return payload as T;
}

async function performRefresh(): Promise<string | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
      method: "POST",
      headers: buildHeaders(),
      credentials: "include",
    });
    const payload = (await parsePayload(response)) as RefreshPayload | null;

    if (!response.ok || !payload?.accessToken) {
      store.dispatch(clearAuth());
      return null;
    }

    store.dispatch(setAccessToken(payload.accessToken));
    return payload.accessToken;
  } catch {
    store.dispatch(clearAuth());
    return null;
  }
}

export async function refreshAccessToken(): Promise<string | null> {
  if (!refreshPromise) {
    refreshPromise = performRefresh().finally(() => {
      refreshPromise = null;
    });
  }

  return refreshPromise;
}

export function apiFetch<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  return request<T>(path, {
    ...options,
    withAuth: true,
    retryOnUnauthorized: true,
  });
}

export function authFetch<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  return request<T>(path, {
    ...options,
    withAuth: false,
    retryOnUnauthorized: false,
  });
}
```

Why this API design is important:

- Prevents duplicated fetch/auth logic across pages.
- Handles `401` -> refresh -> retry once in one place.
- Avoids recursive refresh loops.
- Surfaces backend errors through `ApiError`.

## Step 5: Add Auth API Functions

Create `frontend/src/features/auth/api.ts`:

```ts
import { authFetch, refreshAccessToken } from "../../lib/api";

export interface AccessTokenResponse {
  accessToken: string;
}

export interface RegisterResponse {
  id: string;
  email: string;
  created_at: string;
}

export interface LogoutResponse {
  message: string;
}

export function loginRequest(
  email: string,
  password: string,
): Promise<AccessTokenResponse> {
  return authFetch<AccessTokenResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export function registerRequest(
  email: string,
  password: string,
): Promise<RegisterResponse> {
  return authFetch<RegisterResponse>("/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function refreshRequest(): Promise<AccessTokenResponse> {
  const accessToken = await refreshAccessToken();

  if (!accessToken) {
    throw new Error("Unable to refresh session");
  }

  return { accessToken };
}

export function logoutRequest(): Promise<LogoutResponse> {
  return authFetch<LogoutResponse>("/auth/logout", {
    method: "POST",
  });
}
```

## Step 6: Add Form Validation Schemas

Create `frontend/src/features/auth/loginSchema.ts`:

```ts
import * as yup from "yup";

export const loginSchema = yup.object({
  email: yup
    .string()
    .required("Email is required")
    .email("Invalid email format"),

  password: yup
    .string()
    .required("Password is required")
    .min(6, "Minimum 6 characters"),
});
```

Create `frontend/src/features/auth/registerSchema.ts`:

```ts
import * as yup from "yup";

export const registerSchema = yup.object({
  email: yup.string().required("Email is required").email("Invalid email"),

  password: yup
    .string()
    .required("Password is required")
    .min(6, "Minimum 6 characters"),

  confirmPassword: yup
    .string()
    .required("Password is required")
    .oneOf([yup.ref("password")], "Passwords must match"),
});
```

## Step 7: Add Auth Mutation Hooks

Create `frontend/src/features/auth/useLogin.ts`:

```ts
import { useMutation } from "@tanstack/react-query";
import { useAppDispatch } from "../../store/hooks";
import { loginRequest } from "./api";
import { setAccessToken } from "../../store/authSlice/authSlice";

export function useLogin() {
  const dispatch = useAppDispatch();

  return useMutation({
    mutationFn: ({ email, password }: { email: string; password: string }) =>
      loginRequest(email, password),
    onSuccess: (data) => {
      dispatch(setAccessToken(data.accessToken));
    },
  });
}
```

Create `frontend/src/features/auth/useRegister.ts`:

```ts
import { useMutation } from "@tanstack/react-query";
import { useAppDispatch } from "../../store/hooks";
import { loginRequest, registerRequest } from "./api";
import { setAccessToken } from "../../store/authSlice/authSlice";

export function useRegister() {
  const dispatch = useAppDispatch();

  return useMutation({
    mutationFn: async ({
      email,
      password,
    }: {
      email: string;
      password: string;
    }) => {
      await registerRequest(email, password);

      return loginRequest(email, password);
    },

    onSuccess: (data) => {
      dispatch(setAccessToken(data.accessToken));
    },
  });
}
```

Create `frontend/src/features/auth/useLogout.ts`:

```ts
import { useMutation } from "@tanstack/react-query";
import { clearAuth } from "../../store/authSlice/authSlice";
import { useAppDispatch } from "../../store/hooks";
import { logoutRequest } from "./api";

export function useLogout() {
  const dispatch = useAppDispatch();

  return useMutation({
    mutationFn: logoutRequest,
    onSuccess: () => {
      dispatch(clearAuth());
    },
  });
}
```

## Step 8: Add Route Guards

Create `frontend/src/routes/ProtectedRoute.tsx`:

```tsx
import type { ReactElement } from "react";
import { useAppSelector } from "../store/hooks";
import { Navigate } from "react-router-dom";

interface ProtectedRouteProps {
  children: ReactElement;
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { accessToken, isAuthInitialized } = useAppSelector(
    (state) => state.auth,
  );

  if (!isAuthInitialized) {
    return null;
  }

  if (!accessToken) {
    return <Navigate to="/login" replace />;
  }

  return children;
}
```

Create `frontend/src/routes/PublicRoute.tsx`:

```tsx
import type { ReactElement } from "react";
import { Navigate } from "react-router-dom";
import { useAppSelector } from "../store/hooks";

interface PublicRouteProps {
  children: ReactElement;
}

export function PublicRoute({ children }: PublicRouteProps) {
  const { accessToken, isAuthInitialized } = useAppSelector(
    (state) => state.auth,
  );

  if (!isAuthInitialized) {
    return null;
  }

  if (accessToken) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
}
```

## Step 9: Build Login and Register Pages

Create `frontend/src/pages/Login.tsx`:

```tsx
import { useLogin } from "../features/auth/useLogin";
import { useForm } from "react-hook-form";
import { yupResolver } from "@hookform/resolvers/yup";
import { loginSchema } from "../features/auth/loginSchema";
import { ApiError } from "../lib/api";
import { Link, useNavigate } from "react-router-dom";

interface LoginFormInputs {
  email: string;
  password: string;
}

export function Login() {
  const { mutate, isPending, isError, error } = useLogin();
  const navigate = useNavigate();

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormInputs>({
    resolver: yupResolver(loginSchema),
  });

  function onSubmit(data: LoginFormInputs) {
    mutate(data, {
      onSuccess: () => {
        navigate("/dashboard", { replace: true });
      },
    });
  }

  const errorMessage =
    error instanceof ApiError ? error.message : "Invalid credentials";

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <form
        onSubmit={handleSubmit(onSubmit)}
        className="bg-white p-6 rounded-lg shadow-md w-80"
      >
        <h2 className="text-xl font-semibold mb-4 text-center">Login</h2>

        <input
          {...register("email")}
          placeholder="Email"
          className="w-full mb-1 px-3 py-2 border rounded"
        />

        {errors.email && (
          <p className="text-red-500 text-sm mb-2">{errors.email.message}</p>
        )}

        <input
          type="password"
          {...register("password")}
          placeholder="Password"
          className="w-full mb-1 px-3 py-2 border rounded"
        />

        {errors.password && (
          <p className="text-red-500 text-sm mb-3">{errors.password.message}</p>
        )}

        <button
          type="submit"
          disabled={isPending}
          className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50"
        >
          {isPending ? "Logging in..." : "Login"}
        </button>

        {isError && (
          <p className="text-red-500 mt-3 text-sm text-center">
            {errorMessage}
          </p>
        )}

        <p className="mt-3 text-sm text-center text-gray-600">
          Don&apos;t have an account?{" "}
          <Link className="text-blue-600 hover:underline" to="/register">
            Register
          </Link>
        </p>
      </form>
    </div>
  );
}
```

Create `frontend/src/pages/Register.tsx`:

```tsx
import { useForm } from "react-hook-form";
import { useRegister } from "../features/auth/useRegister";
import { yupResolver } from "@hookform/resolvers/yup";
import { registerSchema } from "../features/auth/registerSchema";
import { ApiError } from "../lib/api";
import { Link, useNavigate } from "react-router-dom";

interface RegisterFormInputs {
  email: string;
  password: string;
  confirmPassword: string;
}

export default function Register() {
  const { mutate, isPending, isError, error } = useRegister();
  const navigate = useNavigate();

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<RegisterFormInputs>({
    resolver: yupResolver(registerSchema),
  });

  function onSubmit(data: RegisterFormInputs) {
    mutate(
      {
        email: data.email,
        password: data.password,
      },
      {
        onSuccess: () => {
          navigate("/dashboard", { replace: true });
        },
      },
    );
  }

  const errorMessage =
    error instanceof ApiError ? error.message : "Registration failed";

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <form
        onSubmit={handleSubmit(onSubmit)}
        className="bg-white p-6 rounded-lg shadow-md w-80"
      >
        <h2 className="text-xl font-semibold mb-4 text-center">Register</h2>

        <input
          {...register("email")}
          placeholder="Email"
          className="w-full mb-1 px-3 py-2 border rounded"
        />
        {errors.email && (
          <p className="text-red-500 text-sm mb-2">{errors.email.message}</p>
        )}

        <input
          type="password"
          {...register("password")}
          placeholder="Password"
          className="w-full mb-1 px-3 py-2 border rounded"
        />
        {errors.password && (
          <p className="text-red-500 text-sm mb-2">{errors.password.message}</p>
        )}

        <input
          type="password"
          {...register("confirmPassword")}
          placeholder="Confirm Password"
          className="w-full mb-1 px-3 py-2 border rounded"
        />
        {errors.confirmPassword && (
          <p className="text-red-500 text-sm mb-3">
            {errors.confirmPassword.message}
          </p>
        )}

        <button
          type="submit"
          disabled={isPending}
          className="w-full bg-green-600 text-white py-2 rounded hover:bg-green-700 disabled:opacity-50"
        >
          {isPending ? "Registering..." : "Register"}
        </button>

        {isError && (
          <p className="text-red-500 mt-3 text-sm text-center">
            {errorMessage}
          </p>
        )}

        <p className="mt-3 text-sm text-center text-gray-600">
          Already have an account?{" "}
          <Link className="text-blue-600 hover:underline" to="/login">
            Login
          </Link>
        </p>
      </form>
    </div>
  );
}
```

## Step 10: Add Dashboard Page with Logout Button

Create `frontend/src/pages/Dashboard.tsx`:

```tsx
import { useNavigate } from "react-router-dom";
import { useLogout } from "../features/auth/useLogout";
import { ApiError } from "../lib/api";

export default function Dashboard() {
  const navigate = useNavigate();
  const { mutate, isPending, isError, error } = useLogout();

  function handleLogout() {
    mutate(undefined, {
      onSuccess: () => {
        navigate("/login", { replace: true });
      },
    });
  }

  const errorMessage =
    error instanceof ApiError ? error.message : "Unable to log out";

  return (
    <div className="min-h-screen bg-gray-100 p-8">
      <div className="mx-auto max-w-5xl rounded-lg border border-dashed border-gray-300 bg-white p-8">
        <div className="flex items-center justify-between gap-4">
          <h1 className="text-2xl font-semibold text-gray-900">Dashboard</h1>
          <button
            type="button"
            className="rounded bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
            onClick={handleLogout}
            disabled={isPending}
          >
            {isPending ? "Logging out..." : "Logout"}
          </button>
        </div>

        {isError && <p className="mt-4 text-sm text-red-600">{errorMessage}</p>}
      </div>
    </div>
  );
}
```

## Step 11: Configure Routing and Auth Bootstrap

Update `frontend/src/App.tsx`:

```tsx
import { useEffect } from "react";
import { Login } from "./pages/Login";
import { useAppDispatch } from "./store/hooks";
import { refreshRequest } from "./features/auth/api";
import {
  clearAuth,
  setAccessToken,
  setAuthInitialized,
} from "./store/authSlice/authSlice";
import Register from "./pages/Register";
import {
  BrowserRouter as Router,
  Navigate,
  Route,
  Routes,
} from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import { ProtectedRoute } from "./routes/ProtectedRoute";
import { PublicRoute } from "./routes/PublicRoute";

function App() {
  const dispatch = useAppDispatch();

  useEffect(() => {
    let isMounted = true;

    async function initializeAuth() {
      try {
        const data = await refreshRequest();

        if (isMounted) {
          dispatch(setAccessToken(data.accessToken));
        }
      } catch {
        if (isMounted) {
          dispatch(clearAuth());
        }
      } finally {
        if (isMounted) {
          dispatch(setAuthInitialized());
        }
      }
    }

    initializeAuth();

    return () => {
      isMounted = false;
    };
  }, [dispatch]);

  return (
    <Router>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />

        <Route
          path="/login"
          element={
            <PublicRoute>
              <Login />
            </PublicRoute>
          }
        />

        <Route
          path="/register"
          element={
            <PublicRoute>
              <Register />
            </PublicRoute>
          }
        />

        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />

        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Router>
  );
}

export default App;
```

## Step 12: Environment Configuration

Create `frontend/.env`:

```env
VITE_API_BASE_URL=http://localhost:5000
```

Why this is needed:

- Keeps API base URL configurable.
- Avoids hardcoding environment-specific backend URLs.

## Step 13: End-to-End Flow (How it works)

1. User opens app.
2. `App.tsx` attempts silent refresh via `/auth/refresh`.
3. If refresh succeeds, user is treated as authenticated.
4. Public pages (`/login`, `/register`) redirect authenticated users to `/dashboard`.
5. Protected pages (`/dashboard`) redirect unauthenticated users to `/login`.
6. Login/Register success stores access token in Redux.
7. Protected API requests send `Authorization: Bearer <token>` automatically.
8. On token expiry, API layer tries `/auth/refresh` and retries once.
9. Logout calls `/auth/logout`, clears auth state, and redirects to `/login`.

## Step 14: Validation Commands

Run these after implementation:

```bash
cd frontend
npm run lint
npx tsc -p tsconfig.app.json --noEmit
npm run dev
```

## Step 15: Implementation Checklist

- [ ] Auth slice created with `accessToken` and `isAuthInitialized`.
- [ ] API client handles refresh and retry safely.
- [ ] Auth APIs wired: login, register, refresh, logout.
- [ ] Login/Register forms validate with Yup.
- [ ] Public and protected routes enforce auth boundaries.
- [ ] Dashboard exists and contains working logout button.
- [ ] Startup refresh flow works after hard refresh.
- [ ] Lint and typecheck pass.

This completes frontend integration of the backend auth flow in a clean, scalable way.
