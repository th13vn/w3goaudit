import { describe, it, expect } from "vitest";
import { TokenBucket, type Clock } from "./ratelimit.js";

/** Virtual clock: sleep advances `t` and resolves immediately. */
function fakeClock(): Clock & { t: number; slept: number[] } {
  const c = {
    t: 0,
    slept: [] as number[],
    now() {
      return c.t;
    },
    async sleep(ms: number) {
      c.slept.push(ms);
      c.t += ms;
    },
  };
  return c;
}

describe("TokenBucket", () => {
  it("allows rps immediate takes, then delays", async () => {
    const clock = fakeClock();
    const tb = new TokenBucket(2, clock);
    expect((await tb.take()).waitedMs).toBe(0);
    expect((await tb.take()).waitedMs).toBe(0);
    const third = await tb.take();
    expect(third.waitedMs).toBeGreaterThan(0); // had to wait for a refill
  });

  it("refills over time", async () => {
    const clock = fakeClock();
    const tb = new TokenBucket(1, clock); // 1 token/sec
    await tb.take(); // consume the initial token
    clock.t += 1000; // a second passes -> 1 token refilled
    expect((await tb.take()).waitedMs).toBe(0);
  });

  it("applies backoff after a 429, and escalates", async () => {
    const clock = fakeClock();
    const tb = new TokenBucket(10, clock);
    tb.onRetryAfter();
    expect(tb.pendingBackoffMs()).toBe(1000);
    const r = await tb.take();
    expect(r.waitedMs).toBeGreaterThanOrEqual(1000);
    tb.onRetryAfter();
    tb.onRetryAfter(); // escalates (doubling)
    expect(tb.pendingBackoffMs()).toBeGreaterThan(1000);
  });

  it("honors a server Retry-After hint when larger", async () => {
    const clock = fakeClock();
    const tb = new TokenBucket(10, clock);
    tb.onRetryAfter(5); // 5 seconds
    expect(tb.pendingBackoffMs()).toBe(5000);
  });
});
