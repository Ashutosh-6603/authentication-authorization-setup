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
    "allowImportingTsExtensions":true,
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

volumes:
  auth_pgdata
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
import { User } from "../types/user.ts";

export const userRepository = {
  async findByEmail(email: string): Promise<User | null> {
    const result = await pool.query<User>(
      `SELECT * FROM users WHERE email = $1`,
      [email]
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
      [email, passwordHash]
    );

    return result.rows[0];
  }
};
```

- Why
  -> Parameterized queries - SQL injection safe
  -> Repository pattern - business logic stays clean
  -> No framework dependencies
