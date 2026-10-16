import express, { Application, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import path from 'path';
import fs from 'fs';
import yaml from 'yamljs';
import swaggerUi from 'swagger-ui-express';
import { config } from './config/environment';
import { RepositoryContainer, getRepositories } from './repositories';
import { createAuthRouter } from './modules/auth/auth.routes';
import { createUserRouter, createAdminRouter } from './modules/users/user.routes';
import { createRateLimiter } from './middleware/rateLimiter';

export interface CreateAppOptions {
  repos?: RepositoryContainer;
  rateLimits?: {
    loginMax?: number;
    registerMax?: number;
    forgotPasswordMax?: number;
    globalMax?: number;
  };
}

export const createApp = (optionsOrRepos?: RepositoryContainer | CreateAppOptions): Application => {
  const app = express();

  let repos: RepositoryContainer;
  let rateLimits: CreateAppOptions['rateLimits'];

  if (optionsOrRepos && 'users' in optionsOrRepos) {
    repos = optionsOrRepos as RepositoryContainer;
  } else if (optionsOrRepos) {
    const opts = optionsOrRepos as CreateAppOptions;
    repos = opts.repos || getRepositories();
    rateLimits = opts.rateLimits;
  } else {
    repos = getRepositories();
  }

  // Helmet Security Headers (adjusted to allow Swagger UI resources)
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:'],
        },
      },
      crossOriginEmbedderPolicy: false,
    })
  );

  // CORS Configuration with strict allowlist
  const allowedOrigins = config.CORS_ORIGIN.split(',').map((origin) => origin.trim());
  app.use(
    cors({
      origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
          callback(null, true);
        } else {
          callback(new Error('Blocked by CORS policy'));
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    })
  );

  // Global Rate Limiter
  const globalMax = rateLimits?.globalMax ?? (config.NODE_ENV === 'test' ? 5000 : config.RATE_LIMIT_MAX_REQUESTS);
  const globalLimiter = createRateLimiter({
    prefix: 'api-global',
    windowMs: config.RATE_LIMIT_WINDOW_MS,
    max: globalMax,
    message: 'Global API rate limit exceeded. Please try again later.',
  });
  app.use('/api', globalLimiter);

  // Request Parsing with strict payload limits (10kb prevents Denial-of-Service via huge payloads)
  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: true, limit: '10kb' }));
  app.use(cookieParser(config.COOKIE_SECRET));

  // Catch malformed JSON payloads and return a clean 400 Bad Request
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    if (err instanceof SyntaxError && 'body' in err) {
      res.status(400).json({
        success: false,
        message: 'Invalid JSON payload format',
      });
      return;
    }
    next(err);
  });

  // Health Check Endpoint
  app.get('/health', (req: Request, res: Response) => {
    res.status(200).json({
      status: 'ok',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      environment: config.NODE_ENV,
      service: 'auth-service',
    });
  });

  // OpenAPI / Swagger Documentation endpoint
  const openApiPath = path.resolve(process.cwd(), 'docs/openapi.yaml');
  if (fs.existsSync(openApiPath)) {
    try {
      const swaggerDoc = yaml.load(openApiPath);
      app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerDoc));
    } catch (e) {
      console.warn('Could not load OpenAPI specification for /api/docs');
    }
  }

  // Mount API Routers
  app.use('/api/auth', createAuthRouter({ repos, rateLimits }));
  app.use('/api/users', createUserRouter(repos));
  app.use('/api/admin', createAdminRouter(repos));

  // 404 Route Handler for undefined endpoints
  app.use((req: Request, res: Response) => {
    res.status(404).json({
      success: false,
      message: `Endpoint ${req.method} ${req.originalUrl} not found`,
    });
  });

  // Centralized Error Handler
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    const statusCode = err.statusCode || (err.status ? Number(err.status) : 500);
    const isProduction = config.NODE_ENV === 'production';

    res.status(statusCode).json({
      success: false,
      message: isProduction && statusCode === 500 ? 'Internal server error' : err.message || 'An error occurred',
      ...(err.errors ? { errors: err.errors } : {}),
      ...(isProduction ? {} : { stack: err.stack }),
    });
  });

  return app;
};
