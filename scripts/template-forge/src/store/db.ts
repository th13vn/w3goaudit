import Database from "better-sqlite3";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export type DB = Database.Database;

/**
 * Open (or create) the SQLite database at `path` and apply migrations
 * idempotently. Pass ":memory:" for tests.
 */
export function openDb(path: string): DB {
  const db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  const migrations = readFileSync(resolve(here, "migrations.sql"), "utf8");
  db.exec(migrations);
  return db;
}
