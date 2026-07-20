export interface Clock {
  now(): number; // ms
  sleep(ms: number): Promise<void>;
}

const realClock: Clock = {
  now: () => Date.now(),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
};

/**
 * Token-bucket rate limiter with 429 backoff. `take()` resolves when a request
 * may proceed; it sleeps as needed to honor `rps`. `onRetryAfter(seconds)` adds
 * an exponential backoff delay applied before the next `take()`.
 *
 * The clock is injectable so tests can run without real time.
 */
export class TokenBucket {
  private tokens: number;
  private last: number;
  private readonly refillPerMs: number;
  private backoffMs = 0;

  constructor(
    private readonly rps: number,
    private readonly clock: Clock = realClock,
  ) {
    this.refillPerMs = rps / 1000;
    this.tokens = rps; // start full
    this.last = clock.now();
  }

  private refill(): void {
    const t = this.clock.now();
    this.tokens = Math.min(
      this.rps,
      this.tokens + (t - this.last) * this.refillPerMs,
    );
    this.last = t;
  }

  /** Wait until a token is available (and any pending backoff has elapsed). */
  async take(): Promise<{ waitedMs: number }> {
    let waited = 0;
    if (this.backoffMs > 0) {
      await this.clock.sleep(this.backoffMs);
      waited += this.backoffMs;
      this.backoffMs = 0;
    }
    this.refill();
    if (this.tokens < 1) {
      const need = (1 - this.tokens) / this.refillPerMs;
      await this.clock.sleep(need);
      waited += need;
      this.refill();
    }
    this.tokens -= 1;
    return { waitedMs: waited };
  }

  /**
   * Register a 429 / Retry-After. Sets an exponential backoff (doubling, capped
   * at 60s) applied before the next take. `seconds` (server hint) takes
   * precedence when larger.
   */
  onRetryAfter(seconds?: number): void {
    const hinted = (seconds ?? 0) * 1000;
    const next = this.backoffMs > 0 ? this.backoffMs * 2 : 1000;
    this.backoffMs = Math.min(Math.max(next, hinted), 60_000);
  }

  /** Current pending backoff (ms) — exposed for tests/telemetry. */
  pendingBackoffMs(): number {
    return this.backoffMs;
  }
}
