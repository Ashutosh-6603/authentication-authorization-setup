# STEPS

## STEP - 1 - Create backend project

```perl
auth-system/
 ├─ backend/
 └─ docker/
```

- Move into the backend folder

```bash
cd backend
npm init -y
```

## STEP - 2 - Install dependencies

- Run the command

```bash
npm install express dotenv cors pg
npm install --save-dev nodemon
npm install -D typescript ts-node nodemon @types/node @types/express @types/cors
npm i --save-dev @types/pg
```

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

## STEP - 3 - Configure TypeScript

- Run the command

```bash
npx tsc --init
```

- Go to `backend/tsconfig.json`

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

## STEP - 4 - Dev Script

- Change this in the package.json file

```json
{
  "type": "module",
  "scripts": {
    "dev": "nodemon --exec ts-node src/index.ts"
  }
}
```

## STEP - 5 - Create a minimal server using express

- Create `backend/src/index.ts`

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

- The `/health` endpoint is mandatory for infra and monitoring

- Run the command

```bash
npm run dev
```

- Add the `.env` file in the `backend` folder

```env
PORT=5000
```

- Create the `.gitignore` file in the `backend` folder

```gitignore
node_modules
dist
.env
```

## STEP - 6 - Setup PostgreSQL Database via Docker

- Create a file `docker/docker-compose.yml`

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

- Run the command

```bash
cd docker

docker compose up -d
```

- Add the following to the env file

```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=auth_db
DB_USER=auth_user
DB_PASSWORD=auth_password
```

## STEP - 7 - PostgreSQL Connection

- Create the file `backend/src/db.ts`

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

- `Pool` is required for concurrency

## STEP - 8 - Database Connectivity test

- Update `backend/src/index.ts`

```ts
import { pool } from "./db.js";

app.get("/db-test", async (_req, res) => {
  const result = await pool.query("SELECT NOW()");
  res.json(result.rows[0]);
});
```

## STEP - 9 - Set up Authentication Database Schema (PostgreSQL)

- Go to DBeaver and open the sql script for the `auth_db` database and start writing queries

- Enable `UUID` support

```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```

- Why
  -> UUIDs are safer than incremental IDs
  -> Better for distributed systems
  -> Avoids user enumeration

- Create the `users` table

```sql
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

- Why
  -> `email UNIQUE` -> login identity
  -> `password_hash` -> never store passwords
  -> `is_active` -> soft-disable users
  -> `created_at` -> auditing

- Create the `roles` table

```sql
CREATE TABLE roles (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);
```

- Why
  -> Roles change rarely
  -> `SERIAL` is fine here (internal use only)
  -> Separate tables enable RBAC scaling

- Create `Seed` roles

```sql
INSERT INTO roles (name)
VALUES
  ('user'),
  ('admin'),
  ('super-admin');
```

- Why
  -> Fixed roles
  -> Enforced by DB itself, not code enums

- `user_roles` (many-to-many)

```sql
CREATE TABLE user_roles (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id INT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
```

- Why
  -> Users can have multiple roles
  -> `ON DELETE CASCADE` keeps data clean
  -> Composite PK prevents duplicates

- Indexes (important, minimal)

```sql
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
```

- Why
  -> Login is email based
  -> Role lookup happens on every request.

## STEP - 10 - Type-safe DB Access layer (Users)

- Create DB types, so create the file `backend/src/types/user.ts`

```ts
export interface User {
  id: string;
  email: string;
  password_hash: string;
  is_active: boolean;
  created_at: Date;
}
```

- Why
  -> Central source of truth
  -> Prevents "any"-driven bug
  -> Mirrors DB exactly (important)

- Create users repository, create the file `backend/src/repositories/user.repository.ts`

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

- Why
  -> Parameterized queries - SQL injection safe
  -> Repository pattern - business logic stays clean
  -> No framework dependencies

- Temporary test endpoint (sanity only)

- Update 'backend/src/index.ts'

```ts
import { userRepository } from "./repositories/user.repository.ts";

app.post("/test-user", async (req, res) => {
  const { email } = req.body;

  const user = await userRepository.create(email, "dummy_password_hash");

  res.json(user);
});
```

- Test it in Postman

## STEP - 11 - User Registration and Password Hashing and Validation

- Install required dependencies

```bash
npm install bcrypt
npm install -D @types/bcrypt
```

- Why
  -> `bcrypt` is battle-tested
  -> Slow hashing - brute-force resistant

- Create the password hashing utility, create the file `backend/src/utils/password.ts`

```ts
import bcrypt from "bcrypt";

const SALT_ROUNDS = 12;

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}
```

- Why
  -> Centralized hashing logic
  -> Easy to tune cost factor later

- Extend user repository for role Assignment

- Update 'backend/src/repositories/user.repository.ts'

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

- Why
  -> DB decides role ID
  -> No hardcoded role numbers
  -> Safe and scalable

- Create user registration endpoint

- Create the file `backend/src/controllers/auth.controller.ts`

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

- Why
  -> Validation first
  -> Hash before DB insert
  -> Default role assignment is explicit

- Create the auth routes file

- Create the file `backend/src/routes/auth.routes.ts`

```ts
import { Router } from "express";
import { register } from "../controllers/auth.controller.ts";

export const authRouter = Router();

authRouter.post("/register", register);
```

- Wire routes and remove test endpoint

- Update 'backend/src/index.ts'

```ts
import { authRouter } from "./routes/auth.routes.ts";

app.use("/auth", authRouter);
```

## STEP - 12 - Login and JWT Access Token (Authentication Core)

- Install the jwt dependencies

```bash
npm install jsonwebtoken
npm install -D @types/jsonwebtoken
```

- Why
  -> Stateless auth
  -> Scales Horizontally
  -> Industry standard for APIs

- Create the JWT utility

- Create the file `backend/src/utils/jwt.ts`

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

- Why
  -> Centralized token logic
  -> Short expiry - safer
  -> Typed payload

- Add JWT secret to the `env` file

```env
JWT_SECRET=super_secret_jwt_key_change_later
```

- Why
  -> Never hardcode secrets
  -> Will rotate later

- Create the login controller

- Add the api to the `backend/src/controllers/auth.controller.ts`

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

- Why
  -> Same error for wrong email/password (security)
  -> Token contains only usedId
  -> No rotes yet (intentional)

- Add the login route to the `auth.routes.ts` file

```ts
import { login } from "../controllers/auth.controller.ts";

authRouter.post("/login", login);
```

- Create the Auth middleware

- Create the file `backend/src/middlewares/auth.middleware.ts`

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

- Why
  -> Backend-enforced auth
  -> Token verification per request
  -> Types request extension

- Test the protected route

- Add this temporary route in `index.ts`

```ts
import { requireAuth } from "./middlewares/auth.middleware.ts";

app.get("/protected", requireAuth, (req, res) => {
  res.json({ message: "You are authenticated" });
});
```

- Login

```postman
POST /auth/login
{
  "email": "user1@example.com",
  "password": "User@1"
}
```

- Use token in the protected route

```postman
GET /protected
Authorization: Bearer <token>
```

## STEP - 13 - Refresh Tokens + Logout (Session Control)

- Go to DBeaver and write the query to generate the table for refresh tokens

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

- Why?
  -> Enables logout and session invalidation
  -> Supports multiple devices later
  -> DB-backed security

- Install the cookie support packages

```bash
npm install cookie-parser
npm install -D @types/cookie-parser
```

- Wire the cookie parser into the `index.ts` file

```ts
import cookieParser from "cookie-parser";

app.use(cookieParser());
```

- Why
  -> Read `HttpOnly` cookies safely
  -> Required for refresh flow

- Create the file `backend/src/utils/refreshToken.ts`

```ts
import crypto from "crypto";

export function generateRefreshToken(): string {
  return crypto.randomBytes(64).toString("hex");
}
```

- Why
  -> Not JWT
  -> Fully random
  -> Safer for long-lived tokens

- Extend user repository

- Update the file `backend/src/repositories/user.repository.ts`

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

- Why
  -> Explicit lifecycle control
  -> DB decides session validity

- Issue refresh token on login
- Update login controller (`backend/src/controllers/auth.controller.ts`)

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

- Why
  -> Refresh token never touches JS
  -> Cookie is CSRF-resistant(sameSite)
  -> Expiry enforced by DB + browser

- Refresh Endpoint (`backend/src/controllers/auth.controller.ts`)

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

- You will get an error in after creating the `refresh` endpoint regarding types. So create the file `backend/src/types/refresh-token.ts`

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

- and then update the `user.repository.ts` file

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

- Now you will see that the auth controller has no error in the refresh endpoint

- Logout endpoint

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

- Add the routes (`backend/src/routes/auth.routes.ts`)

```ts
authRouter.post("/refresh", refresh);
authRouter.post("/logout", logout);
```

## STEP - 14 - Role Based Authentication (RBAC)

- Update respository (`backend/src/repositories/user.repository.ts`)

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

- Why
  -> DB is the source of truth
  -> Supports multiple roles per user
  -> Scales to permission later

- Extend Auth Request

- Update Auth middleware types (`backend/src/middlewares/auth.middleware.ts`)

```ts
export interface AuthRequest extends Request {
  userId?: string;
  roles?: string[];
}
```

- Role Middleware

- Create the file `backend/src/middlewares/role.middleware.ts`

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

- Why
  - Variadic roles -> flexible
    - admin only
    - admin + super-admin
  - Reusable everywhere

## STEP - 15 - Add Roles into JWT (Performance Optimization)

- Update JWT payload type (`backend/src/utils/jwt.ts`)

```ts
export interface JwtPayload {
  userId: string;
  roles: string[];
}
```

- Include roles when signing token

- Update login controller

```ts
const roles = await userRepository.getUserRoles(user.id);

const accessToken = signAccessToken({
  userId: user.id,
  roles,
});
```

- Why
  - Roles snapshot at login
  - Avoids DB hits per request
  - Token is short-lived anyway

- Update refresh endpoint (`auth.controller.ts`)

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

- Why
  - Role changes propagate on refresh
  - DB still controls long-lived sessions

- Update auth middleware (`backend/src/middlewares/auth.middleware.ts`)

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

- Simplify role middlewares (NO DB CALL) (`backend/src/middlewares/role.middleware.ts`)

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

- Why
  - Zero DB access
  - Extremely fast
  - Clean separation of concerns
