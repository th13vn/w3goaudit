import { describe, it, expect, beforeEach } from "vitest";
import { createStopFlag, withLock, LockHeldError } from "./signals.js";
import { openDb } from "../store/db.js";
import { Repo } from "../store/repo.js";

describe("createStopFlag", () => {
  it("starts unstopped and flips on request", () => {
    const f = createStopFlag();
    expect(f.stopped()).toBe(false);
    f.request();
    expect(f.stopped()).toBe(true);
  });
});

describe("withLock", () => {
  let repo: Repo;
  beforeEach(() => {
    repo = new Repo(openDb(":memory:"));
  });

  it("runs fn while holding the lock and releases after", async () => {
    const r = await withLock(repo, "run-1", async () => 42);
    expect(r).toBe(42);
    // lock released -> can acquire again
    expect(await withLock(repo, "run-2", async () => "ok")).toBe("ok");
  });

  it("throws LockHeldError when the lock is already held", async () => {
    expect(repo.acquireLock("other")).toBe(true);
    await expect(withLock(repo, "run-1", async () => 1)).rejects.toBeInstanceOf(
      LockHeldError,
    );
  });

  it("releases the lock even when fn throws", async () => {
    await expect(
      withLock(repo, "run-1", async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect(repo.acquireLock("run-2")).toBe(true); // was released
  });
});
