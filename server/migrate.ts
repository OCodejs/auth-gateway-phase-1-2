import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pool } from "./db.js";

async function main() {
  const directory = resolve(process.cwd(), "db/migrations");
  const files = (await readdir(directory)).filter(name => /^\d+_[\w-]+\.sql$/.test(name)).sort();
  const client = await pool.connect();
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);
    for (const filename of files) {
      const exists = await client.query("SELECT 1 FROM schema_migrations WHERE filename=$1", [filename]);
      if (exists.rowCount) continue;
      const sql = await readFile(resolve(directory, filename), "utf8");
      await client.query("BEGIN");
      try {
        await client.query(sql);
        await client.query("INSERT INTO schema_migrations(filename) VALUES($1)", [filename]);
        await client.query("COMMIT");
        console.log(`Applied ${filename}`);
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      }
    }
  } finally {
    client.release();
    await pool.end();
  }
}
main().catch((error) => { console.error("Database migration failed:", error); process.exit(1); });
