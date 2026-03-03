import { Pool } from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import * as schema from "../shared/schema";

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required");
}

const url = new URL(process.env.DATABASE_URL);
export const pool = new Pool({
  host: url.hostname,
  port: parseInt(url.port || "5432", 10),
  user: decodeURIComponent(url.username),
  password: decodeURIComponent(url.password),
  database: url.pathname.replace(/^\//, ""),
  ssl: false,
});
export const db = drizzle(pool, { schema });
