import { Pool } from "pg";
import { config } from "./config.js";

export const pool = new Pool({
  connectionString: config.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  application_name: "ocodejs-auth-gateway"
});

pool.on("error", (error) => {
  console.error("Unexpected PostgreSQL pool error", error);
});
