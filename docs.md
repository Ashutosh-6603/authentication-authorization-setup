# Steps

## Backend Integration

## Step 1: Create backend project

- Create the initial structure:

```perl
auth-system/
 â”œâ”€ backend/
 â””â”€ docker/
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

## Step 1: Create React app with Vite

```bash
npm create vite@latest ./
```

- Install required dependencies:

```bash
npm install @reduxjs/toolkit react-redux
```

- Why:
  - Official Redux solution
  - Less boilerplate
  - Immutable updates handled internally

- Create Redux store (`frontend/src/store/index.ts`):

```ts
import { configureStore } from "@reduxjs/toolkit";
import authReducer from "./authSlice";

export const store = configureStore({
  reducer: {
    auth: authReducer,
  },
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
```

- Why:
  - Single source of truth
  - Typed store (important for TS)
  - Scales cleanly

- Auth slice (core state) (`frontend/src/store/authSlice.ts`):

```ts
import { createSlice, PayloadAction } from "@reduxjs/toolkit";

interface AuthState {
  accessToken: string | null;
}

const initialState: AuthState = {
  accessToken: null,
};

const authSlice = createSlice({
  name: "auth",
  initialState,
  reducers: {
    setAccessToken(state, action: PayloadAction<string>) {
      state.accessToken = action.payload;
    },
    clearAuth(state) {
      state.accessToken = null;
    },
  },
});

export const { setAccessToken, clearAuth } = authSlice.actions;
export default authSlice.reducer;
```

- Why:
  - Only access token stored
  - No roles/permissions yet (derived later)
  - Simple, predictable state

- Provide the store in `frontend/src/main.tsx`:

```tsx
import React from "react";
import ReactDOM from "react-dom/client";
import { Provider } from "react-redux";
import { store } from "./store";
import App from "./App";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <Provider store={store}>
    <App />
  </Provider>,
);
```

- Why:
  - Redux becomes globally accessible
  - Required for hooks like `useSelector` and `useDispatch`

- Typed Redux hooks (`frontend/src/store/hooks.ts`):

```ts
import { TypedUseSelectorHook, useDispatch, useSelector } from "react-redux";
import type { RootState, AppDispatch } from "./index";

export const useAppDispatch = () => useDispatch<AppDispatch>();
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector;
```

- Why:
  - Type-safe Redux usage
  - Prevents `any` creep
  - Industry standard

## STEP 2: Tanstack Query Setup + Auth-Aware API Layer

- Install dependencies:

```bash
npm install @tanstack/react-query
```

- Create Query Client (`frontend/src/lib/queryClient.ts`):

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

- Why:
  | Option | Reason |
  | ----------------------------- | ------------------------------------- |
  | `retry: 1` | Avoid infinite retries on 401 |
  | `refetchOnWindowFocus: false` | Prevent surprise background refetches |

- React Query is for server state orchestration, not uncontrolled refetching

- Provide Query Client to app

- Update `main.tsx`

```tsx
import { QueryClientProvider } from "@tanstack/react-query";
import { queryClient } from "./lib/queryClient";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <Provider store={store}>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </Provider>,
);
```

- Central API client (fetch-based)
- Create `frontend/src/lib/api.ts`:

```ts
import { store } from "../store";

const BASE_URL = "http://localhost:5000";

export async function apiFetch(path: string, options: RequestInit = {}) {
  const state = store.getState();
  const token = state.auth.accessToken;

  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token && { Authorization: `Bearer ${token}` }),
      ...options.headers,
    },
    credentials: "include", // required for refresh cookie
  });

  if (!res.ok) {
    throw new Error("Request failed");
  }

  return res.json();
}
```

- Why this architecture:
  - Why not call fetch directly in components?
    - You duplicate headers
    - You duplicate error handling
    - Hard to attach tokens consistently
    - This centralizes all auth behavior.

  - Why use store.getState() instead of passing token manually?
    - React Query functions run outside components
    - Avoids prop-drilling
    - Keeps API layer framework-agnostic

  - Why `credentials: "include"`?
    - Refresh token is stored in HttpOnly cookie
    - Without this, browser won’t send it
    - Required for `/auth/refresh`

  - Why Redux + React Query combination works
    - Redux stores authentication state
    - React Query manages server interaction lifecycle

- Test Infrastructure

- Example usage in a component

```tsx
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "../lib/api";

export function HealthCheck() {
  const { data, isLoading } = useQuery({
    queryKey: ["health"],
    queryFn: () => apiFetch("/health"),
  });

  if (isLoading) return <p>Loading...</p>;

  return <pre>{JSON.stringify(data)}</pre>;
}
```

## STEP 3: Login Mutation + Access Token Storage (Redux + React Query)

- Create the login api function (`src/features/auth/api.ts`)

```ts
import { apiFetch } from "../../lib/api";

export async function loginRequest(email: string, password: string) {
  return apiFetch("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}
```

- Why separate files?:
  - Keeps API layer modular
  - Feature-based structure
  - Scales when auth grows

- Create login mutation hook (`src/features/auth/useLogin.ts`)

```ts
import { useMutation } from "@tanstack/react-query";
import { useAppDispatch } from "../../store/hooks";
import { setAccessToken } from "../../store/authSlice";
import { loginRequest } from "./api";

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

- Install tailwind css

```bash
npm install tailwindcss @tailwindcss/vite
```

- Update the `vite.config.ts` file to include the plugin:

```ts
import { defineConfig } from "vite";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [tailwindcss()],
});
```

- import tailwind to the css file (`frontend/src/index.css`):

```css
@import "tailwindcss";
```

- Create a basic login page (`src/pages/Login.tsx`):

```tsx
import { useState } from "react";
import { useLogin } from "../features/auth/useLogin";

export function Login() {
  const { mutate, isPending, isError } = useLogin();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  function handleSubmit(e: ChangeEvent<HTMLFormElement>) {
    e.preventDefault();
    mutate({ email, password });
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <form
        onSubmit={handleSubmit}
        className="bg-white p-6 rounded-lg shadow-md w-80"
      >
        <h2 className="text-xl font-semibold mb-4 text-center">Login</h2>

        <input
          className="w-full mb-3 px-3 py-2 border rounded"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />

        <input
          className="w-full mb-4 px-3 py-2 border rounded"
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <button
          className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700"
          disabled={isPending}
        >
          {isPending ? "Logging in..." : "Login"}
        </button>

        {isError && <p className="text-red-500 mt-2 text-sm">Login failed</p>}
      </form>
    </div>
  );
}
```

- Why store only accessToken in Redux?
  - Because:
    - It is short-lived
    - It is needed globally
    - It changes over time
  - We do not store
    - Refresh token (cookie)
    - User data yet
    - Roles separately
