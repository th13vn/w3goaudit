import { createHash } from "node:crypto";
import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { FORGE_ROOT } from "../config.js";

const CACHE_DIR = resolve(FORGE_ROOT, "cache");

function keyPath(namespace: string, key: string): string {
  const dir = join(CACHE_DIR, namespace);
  mkdirSync(dir, { recursive: true });
  const h = createHash("sha1").update(key).digest("hex").slice(0, 24);
  return join(dir, `${h}.txt`);
}

/** Read a cached value, or undefined if not cached. */
export function cacheGet(namespace: string, key: string): string | undefined {
  const p = keyPath(namespace, key);
  return existsSync(p) ? readFileSync(p, "utf8") : undefined;
}

export function cacheSet(namespace: string, key: string, value: string): void {
  writeFileSync(keyPath(namespace, key), value);
}

/**
 * Return the cached value for `key`, else call `produce`, cache, and return it.
 * Makes every network fetch idempotent across runs (resume never re-fetches).
 */
export async function cached(
  namespace: string,
  key: string,
  produce: () => Promise<string>,
): Promise<string> {
  const hit = cacheGet(namespace, key);
  if (hit !== undefined) return hit;
  const value = await produce();
  cacheSet(namespace, key, value);
  return value;
}
