import express, { Application, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { config } from './config/environment';
import { RepositoryContainer, getRepositories } from './repositories';
import { createAuthRouter } from './modules/auth/auth.routes';

export const createApp = (customRepos?: RepositoryContainer): Application => {
  const app = express();
  const repos = customRepos || getRepositories();

  // Security Headers
  app.use(helmet());

  // CORS Configuration
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

  // Request Parsing with strict payload limits
  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: true, limit: '10kb' }));
  app.use(cookieParser(config.COOKIE_SECRET));

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

  // Mount Auth Router
  app.use('/api/auth', createAuthRouter(repos));

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
