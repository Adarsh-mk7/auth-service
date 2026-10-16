import { Request, Response, NextFunction } from 'express';
import Redis from 'ioredis';
import { config } from '../config/environment';

export interface RateLimitResult {
  count: number;
  resetTimeMs: number;
}

export interface IRateLimiterStore {
  increment(key: string, windowMs: number): Promise<RateLimitResult>;
  reset(key: string): Promise<void>;
}

/**
 * In-memory sliding window rate limiter store.
 * Acts as primary store when Redis is unconfigured, or automatic fallback if Redis is down.
 */
export class MemoryRateLimiterStore implements IRateLimiterStore {
  private hits = new Map<string, { count: number; resetTimeMs: number }>();

  async increment(key: string, windowMs: number): Promise<RateLimitResult> {
    const now = Date.now();
    const entry = this.hits.get(key);

    if (!entry || entry.resetTimeMs <= now) {
      const newEntry = { count: 1, resetTimeMs: now + windowMs };
      this.hits.set(key, newEntry);
      return newEntry;
    }

    entry.count += 1;
    return entry;
  }

  async reset(key: string): Promise<void> {
    this.hits.delete(key);
  }

  clear(): void {
    this.hits.clear();
  }
}

/**
 * Distributed Redis rate limiter store using atomic transactions.
 */
export class RedisRateLimiterStore implements IRateLimiterStore {
  private redis: Redis;
  private fallbackStore: MemoryRateLimiterStore;
  private isConnected = false;

  constructor(redisUrl: string) {
    this.fallbackStore = new MemoryRateLimiterStore();
    this.redis = new Redis(redisUrl, {
      lazyConnect: true,
      maxRetriesPerRequest: 1,
      retryStrategy: (times) => {
        if (times > 3) return null; // Stop retrying after 3 failures, rely on fallback
        return Math.min(times * 100, 1000);
      },
    });

    this.redis.on('connect', () => {
      this.isConnected = true;
    });

    this.redis.on('error', (err) => {
      this.isConnected = false;
      // In production or test, log warning and use fallback without crashing
      if (config.NODE_ENV !== 'test') {
        console.warn(`[RedisRateLimiter] Redis connection issue: ${err.message}. Using In-Memory fallback.`);
      }
    });
  }

  async increment(key: string, windowMs: number): Promise<RateLimitResult> {
    if (!this.isConnected) {
      return this.fallbackStore.increment(key, windowMs);
    }

    try {
      const redisKey = `ratelimit:${key}`;
      const multi = this.redis.multi();
      multi.incr(redisKey);
      multi.pttl(redisKey);
      const results = await multi.exec();

      if (!results || results[0][0]) {
        return this.fallbackStore.increment(key, windowMs);
      }

      const count = results[0][1] as number;
      let ttl = results[1][1] as number;

      // If key had no TTL (-1) or was newly created, set TTL
      if (ttl < 0) {
        await this.redis.pexpire(redisKey, windowMs);
        ttl = windowMs;
      }

      return {
        count,
        resetTimeMs: Date.now() + ttl,
      };
    } catch {
      return this.fallbackStore.increment(key, windowMs);
    }
  }

  async reset(key: string): Promise<void> {
    try {
      if (this.isConnected) {
        await this.redis.del(`ratelimit:${key}`);
      }
    } finally {
      await this.fallbackStore.reset(key);
    }
  }
}

// Store singleton instance
let rateLimiterStore: IRateLimiterStore;

export const getRateLimiterStore = (): IRateLimiterStore => {
  if (!rateLimiterStore) {
    if (config.REDIS_ENABLED && config.REDIS_URL) {
      rateLimiterStore = new RedisRateLimiterStore(config.REDIS_URL);
    } else {
      rateLimiterStore = new MemoryRateLimiterStore();
    }
  }
  return rateLimiterStore;
};

export const setRateLimiterStore = (store: IRateLimiterStore): void => {
  rateLimiterStore = store;
};

export interface RateLimiterOptions {
  windowMs: number;
  max: number;
  message?: string;
  prefix?: string;
  keyGenerator?: (req: Request) => string;
}

export const createRateLimiter = (options: RateLimiterOptions) => {
  const {
    windowMs,
    max,
    message = 'Too many requests. Please try again later.',
    prefix = 'global',
    keyGenerator = (req: Request) => req.ip || req.socket.remoteAddress || 'unknown-ip',
  } = options;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const clientKey = keyGenerator(req);
      const compositeKey = `${prefix}:${clientKey}`;
      const store = getRateLimiterStore();

      const { count, resetTimeMs } = await store.increment(compositeKey, windowMs);
      const remaining = Math.max(0, max - count);
      const resetSeconds = Math.ceil(resetTimeMs / 1000);
      const retryAfterSeconds = Math.ceil((resetTimeMs - Date.now()) / 1000);

      // Standard RateLimit Headers
      res.setHeader('RateLimit-Limit', max);
      res.setHeader('RateLimit-Remaining', remaining);
      res.setHeader('RateLimit-Reset', resetSeconds);

      if (count > max) {
        res.setHeader('Retry-After', retryAfterSeconds);
        res.status(429).json({
          success: false,
          message,
          retryAfter: retryAfterSeconds,
        });
        return;
      }

      next();
    } catch (error) {
      // In case of rate limiter store unexpected errors, fail open to prevent blocking legitimate users
      next();
    }
  };
};
