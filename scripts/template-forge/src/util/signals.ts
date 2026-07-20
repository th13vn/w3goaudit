export interface StopFlag {
  /** True once a graceful stop has been requested. */
  stopped(): boolean;
  /** Request a graceful stop. */
  request(): void;
}

export function createStopFlag(): StopFlag {
  let flag = false;
  return {
    stopped: () => flag,
    request: () => {
      flag = true;
    },
  };
}

/**
 * Install SIGINT/SIGTERM handlers that flip the stop flag for a graceful pause.
 * A SECOND signal forces an immediate exit. Returns an uninstall function.
 */
export function installSignalHandlers(
  flag: StopFlag,
  onFirst?: () => void,
): () => void {
  let count = 0;
  const handler = () => {
    count++;
    if (count >= 2) {
      console.error("\nSecond signal — exiting immediately.");
      process.exit(130);
    }
    console.error("\nStop requested — finishing the current step, then pausing…");
    flag.request();
    onFirst?.();
  };
  process.on("SIGINT", handler);
  process.on("SIGTERM", handler);
  return () => {
    process.off("SIGINT", handler);
    process.off("SIGTERM", handler);
  };
}

export class LockHeldError extends Error {}

/**
 * Run `fn` while holding the single-writer lock, releasing it afterward (even on
 * throw). Throws LockHeldError if another run holds the lock.
 */
export async function withLock<T>(
  lock: { acquireLock(owner: string): boolean; releaseLock(owner: string): void },
  owner: string,
  fn: () => Promise<T>,
): Promise<T> {
  if (!lock.acquireLock(owner)) {
    throw new LockHeldError(
      "another template-forge run holds the lock; wait for it to finish or pause it",
    );
  }
  try {
    return await fn();
  } finally {
    lock.releaseLock(owner);
  }
}
