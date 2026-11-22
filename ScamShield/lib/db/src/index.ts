import { drizzle as drizzlePg, type NodePgDatabase } from "drizzle-orm/node-postgres";
import { drizzle as drizzlePglite } from "drizzle-orm/pglite";
import { PGlite } from "@electric-sql/pglite";
import pg from "pg";
import path from "node:path";
import fs from "node:fs";
import * as schema from "./schema";

const { Pool } = pg;

let pool: pg.Pool | null = null;
let pgliteInstance: PGlite | null = null;
let dbInstance: any = null;

const databaseUrl = process.env.DATABASE_URL;
// Check if DATABASE_URL is set and is not the placeholder localhost url from .env.example
const hasValidPostgresUrl =
  Boolean(databaseUrl) &&
  (databaseUrl!.startsWith("postgres://") || databaseUrl!.startsWith("postgresql://")) &&
  !databaseUrl!.includes("user:password@localhost:5432");

if (hasValidPostgresUrl) {
  try {
    pool = new Pool({ connectionString: databaseUrl });
    dbInstance = drizzlePg(pool, { schema });
  } catch (err) {
    console.warn("Failed to initialize PostgreSQL pool with DATABASE_URL; falling back to embedded database:", err);
  }
}

if (!dbInstance) {
  const dataDir = path.resolve(process.cwd(), "data", "scamshield-db");
  try {
    fs.mkdirSync(dataDir, { recursive: true });
    pgliteInstance = new PGlite(dataDir);
  } catch {
    pgliteInstance = new PGlite();
  }
  dbInstance = drizzlePglite(pgliteInstance, { schema });
}

export const db: NodePgDatabase<typeof schema> = dbInstance;
export { pool, pgliteInstance };
export * from "./schema";
export * from "drizzle-orm";

export async function ensureDatabaseReady() {
  const initSql = `
    CREATE TABLE IF NOT EXISTS scamshield_scans (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      kind TEXT NOT NULL,
      file_name TEXT,
      file_type TEXT,
      target TEXT NOT NULL,
      size_bytes INTEGER,
      sha256 TEXT,
      sha1 TEXT,
      verdict TEXT NOT NULL,
      indicators TEXT[] NOT NULL DEFAULT ARRAY[]::text[],
      detection_source TEXT NOT NULL,
      scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS scamshield_scans_scanned_at_idx ON scamshield_scans(scanned_at);
    CREATE INDEX IF NOT EXISTS scamshield_scans_verdict_idx ON scamshield_scans(verdict);
    CREATE INDEX IF NOT EXISTS scamshield_scans_kind_idx ON scamshield_scans(kind);
  `;
  try {
    if (pgliteInstance) {
      await pgliteInstance.exec(initSql);
    } else if (pool) {
      await pool.query(initSql);
    }
  } catch (err) {
    console.error("Failed to ensure database tables are created:", err);
  }
}
