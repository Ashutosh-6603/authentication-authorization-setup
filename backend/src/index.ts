// package imports
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";

// local imports
import { pool } from "./db.ts";
import { userRepository } from "./repositories/user.repository.ts";
import { authRouter } from "./routes/auth.routes.ts";
import { requireAuth } from "./middlewares/auth.middleware.ts";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 5000;

// Middlewares
app.use(cors());
app.use(express.json());
app.use(cookieParser());

// Enter your endpoints here
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.get("/db-test", async (_req, res) => {
  const result = await pool.query("SELECT NOW()");
  res.json(result.rows[0]);
});

app.use("/auth", authRouter);

// End your endpoints here

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
