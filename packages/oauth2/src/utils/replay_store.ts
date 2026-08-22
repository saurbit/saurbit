/**
 * A generic store for tracking seen values and detecting replays.
 * Used to prevent reuse of one-time tokens such as JTI claims.
 *
 * @template T - The type of values stored (string or number).
 */
export interface ReplayStore<T extends string | number> {
  /**
   * Returns `true` if the value is currently tracked (i.e. has been seen and not yet expired).
   * @param value - The value to check.
   */
  has(value: T): Promise<boolean>;

  /**
   * Removes a value from the store before its TTL expires.
   * @param value - The value to remove.
   */
  delete(value: T): Promise<void>;

  /**
   * Adds a value to the store. The value will be automatically removed after `ttlSeconds`.
   * If the value already exists, its TTL is reset.
   * @param value - The value to track.
   * @param ttlSeconds - Lifetime in seconds before the value is automatically removed.
   */
  add(value: T, ttlSeconds: number): Promise<void>;
}

/**
 * In-memory implementation of {@link ReplayStore} backed by a plain object with `setTimeout`-based expiry.
 *
 * Suitable for single-process deployments. For distributed or multi-process environments,
 * provide a custom {@link ReplayStore} implementation backed by a shared store (e.g. Redis).
 *
 * @template T - The type of values stored. Defaults to `string | number`.
 */
export class InMemoryReplayStore<T extends string | number = string | number>
  implements ReplayStore<T> {
  private values: Record<string, ReturnType<typeof setTimeout>> = {};

  /**
   * Returns `true` if the value is currently tracked.
   * @param value - The value to check.
   */
  async has(value: T): Promise<boolean> {
    if (this.values[`${value}`]) {
      return await Promise.resolve(true);
    }
    return await Promise.resolve(false);
  }

  /**
   * Removes a value from the store and clears its expiry timer.
   * @param value - The value to remove.
   */
  async delete(value: T): Promise<void> {
    delete this.values[`${value}`];
    return await Promise.resolve();
  }

  /**
   * Adds a value to the store with an automatic expiry.
   * If the value already exists, its TTL timer is reset.
   * @param value - The value to track.
   * @param ttlSeconds - Lifetime in seconds before the value is automatically removed.
   */
  async add(value: T, ttlSeconds: number): Promise<void> {
    const to = this.values[`${value}`];
    if (to) {
      clearTimeout(to);
    }
    this.values[`${value}`] = setTimeout(async () => {
      await this.delete(value);
    }, ttlSeconds * 1000);

    return await Promise.resolve();
  }

  /**
   * Clears all tracked values and their expiry timers.
   */
  async clear(): Promise<void> {
    for (const key in this.values) {
      clearTimeout(this.values[key]);
      delete this.values[key];
    }
    return await Promise.resolve();
  }
}

/**
 * Specialization of {@link ReplayStore} for string values.
 * Used to detect replayed tokens via their JTI claim or token string.
 */
export type ReplayDetector = ReplayStore<string>;

/**
 * Creates a new {@link InMemoryReplayStore} instance.
 *
 * @template T - The type of values stored. Defaults to `string | number`.
 * @returns A new in-memory replay store.
 */
export function createInMemoryReplayStore<
  T extends string | number = string | number,
>(): InMemoryReplayStore<T> {
  return new InMemoryReplayStore<T>();
}
