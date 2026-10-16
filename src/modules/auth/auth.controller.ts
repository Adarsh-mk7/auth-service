import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../../services/auth.service';
import { setRefreshTokenCookie, REFRESH_TOKEN_COOKIE_NAME } from '../../utils/cookie';
import { AuthenticatedRequest } from '../../types';
import { UnauthorizedError } from '../../utils/errors';

export class AuthController {
  constructor(private authService: AuthService) {}

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
      // Refresh token can come from signed/unsigned cookie or request body as fallback
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
