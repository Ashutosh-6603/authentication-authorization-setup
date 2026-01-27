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
    "skipLibCheck": true
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

<!-- Check the error after starting the server -->