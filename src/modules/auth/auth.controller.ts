import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../../services/auth.service';
import { SessionService } from '../../services/session.service';
import { setRefreshTokenCookie, clearRefreshTokenCookie, REFRESH_TOKEN_COOKIE_NAME } from '../../utils/cookie';
import { AuthenticatedRequest } from '../../types';
import { UnauthorizedError } from '../../utils/errors';

export class AuthController {
  constructor(
    private authService: AuthService,
    private sessionService: SessionService
  ) {}

  register = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const ipAddress = req.ip || req.socket.remoteAddress;
      const userAgent = req.headers['user-agent'];

      const user = await this.authService.register(req.body, ipAddress, userAgent);

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        data: { user },
      });
    } catch (error) {
      next(error);
    }
  };

  login = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const ipAddress = req.ip || req.socket.remoteAddress;
      const userAgent = req.headers['user-agent'];

      const result = await this.authService.login(req.body, ipAddress, userAgent);

      // Set HTTP-only secure cookie for refresh token
      setRefreshTokenCookie(res, result.refreshToken);

      res.status(200).json({
        success: true,
        message: 'Authentication successful',
        data: {
          user: result.user,
          accessToken: result.accessToken,
        },
      });
    } catch (error) {
      next(error);
    }
  };

  refresh = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const rawToken = req.cookies?.[REFRESH_TOKEN_COOKIE_NAME] || req.body?.refreshToken;

      if (!rawToken) {
        throw new UnauthorizedError('No refresh token provided');
      }

      const ipAddress = req.ip || req.socket.remoteAddress;
      const userAgent = req.headers['user-agent'];

      const result = await this.authService.refreshToken(rawToken, ipAddress, userAgent);

      // Rotate cookie with new refresh token
      setRefreshTokenCookie(res, result.refreshToken);

      res.status(200).json({
        success: true,
        message: 'Tokens refreshed successfully',
        data: {
          user: result.user,
          accessToken: result.accessToken,
        },
      });
    } catch (error) {
      next(error);
    }
  };

  logout = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      const rawToken = req.cookies?.[REFRESH_TOKEN_COOKIE_NAME] || req.body?.refreshToken;
      const userId = req.user?.id;
      const ipAddress = req.ip || req.socket.remoteAddress;
      const userAgent = req.headers['user-agent'];

      await this.sessionService.logout(rawToken, userId, ipAddress, userAgent);

      clearRefreshTokenCookie(res);

      res.status(200).json({
        success: true,
        message: 'Logged out successfully',
      });
    } catch (error) {
      next(error);
    }
  };

  logoutAll = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.user) {
        throw new UnauthorizedError('Authentication required');
      }

      const ipAddress = req.ip || req.socket.remoteAddress;
      const userAgent = req.headers['user-agent'];

      await this.sessionService.logoutAll(req.user.id, ipAddress, userAgent);

      clearRefreshTokenCookie(res);

      res.status(200).json({
        success: true,
        message: 'All active sessions have been revoked',
      });
    } catch (error) {
      next(error);
    }
  };

  getSessions = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.user) {
        throw new UnauthorizedError('Authentication required');
      }

      const rawToken = req.cookies?.[REFRESH_TOKEN_COOKIE_NAME] || req.body?.refreshToken;
      const sessions = await this.sessionService.getActiveSessions(req.user.id, rawToken);

      res.status(200).json({
        success: true,
        message: 'Active sessions retrieved successfully',
        data: { sessions },
      });
    } catch (error) {
      next(error);
    }
  };

  getMe = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.user) {
        throw new UnauthorizedError('Authentication required');
      }

      const user = await this.authService.getMe(req.user.id);

      res.status(200).json({
        success: true,
        message: 'User profile retrieved successfully',
        data: { user },
      });
    } catch (error) {
      next(error);
    }
  };
}
