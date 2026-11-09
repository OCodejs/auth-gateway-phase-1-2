import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pool } from "./db.js";

async function main() {
  const sql = await readFile(resolve(process.cwd(), "db/migrations/001_initial.sql"), "utf8");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(sql);
    await client.query("COMMIT");
    console.log("Database migration 001_initial.sql applied.");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((error) => {
  console.error("Database migration failed:", error);
  process.exit(1);
});
