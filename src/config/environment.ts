import dotenv from 'dotenv';
import { z } from 'zod';

// Load .env file
dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(4000),
  HOST: z.string().default('0.0.0.0'),

  DATABASE_URL: z.string().default('postgresql://auth_user:auth_password@localhost:5432/auth_db?schema=public'),

  REDIS_URL: z.string().default('redis://localhost:6379'),
  REDIS_ENABLED: z.preprocess((val) => val === 'true' || val === true, z.boolean()).default(false),

  JWT_ACCESS_SECRET: z.string().min(16).default('default_access_secret_min_16_chars_long'),
  JWT_REFRESH_SECRET: z.string().min(16).default('default_refresh_secret_min_16_chars_long'),
  JWT_ACCESS_EXPIRY: z.string().default('15m'),
  JWT_REFRESH_EXPIRY_DAYS: z.coerce.number().default(7),
  JWT_ISSUER: z.string().default('auth-service'),
  JWT_AUDIENCE: z.string().default('auth-service-client'),

  COOKIE_SECRET: z.string().min(16).default('default_cookie_secret_min_16_chars_long'),
  COOKIE_SAME_SITE: z.enum(['lax', 'strict', 'none']).default('lax'),
  COOKIE_SECURE: z.preprocess((val) => val === 'true' || val === true, z.boolean()).default(false),

  BCRYPT_SALT_ROUNDS: z.coerce.number().default(10),
  PASSWORD_MIN_LENGTH: z.coerce.number().default(8),
  PASSWORD_RESET_TOKEN_EXPIRY_MINUTES: z.coerce.number().default(15),

  CORS_ORIGIN: z.string().default('http://localhost:3000'),

  RATE_LIMIT_WINDOW_MS: z.coerce.number().default(900000),
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().default(100),
  RATE_LIMIT_AUTH_MAX_REQUESTS: z.coerce.number().default(5),

  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  GOOGLE_CALLBACK_URL: z.string().default('http://localhost:4000/api/auth/google/callback'),

  EMAIL_PROVIDER: z.enum(['mock', 'smtp']).default('mock'),
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().optional(),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  EMAIL_FROM: z.string().default('no-reply@auth-service.local'),
  FRONTEND_URL: z.string().default('http://localhost:3000'),
});

const parseEnv = () => {
  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    // In test environment, provide fallback instead of crashing
    if (process.env.NODE_ENV === 'test') {
      return envSchema.parse({});
    }
    console.error('Invalid environment configuration:', parsed.error.format());
    throw new Error('Environment variable validation failed');
  }
  return parsed.data;
};

export const config = parseEnv();
export type Config = z.infer<typeof envSchema>;
