import { Router, Request, Response, NextFunction } from 'express';
import passport from 'passport';
import crypto from 'crypto';
import { isGoogleOAuthConfigured, configurePassport } from './passport.config';
import { OAuthService, GoogleProfileInput } from './oauth.service';
import { RepositoryContainer, getRepositories } from '../../repositories';
import { setRefreshTokenCookie } from '../../utils/cookie';
import { config } from '../../config/environment';

const OAUTH_STATE_COOKIE = 'oauth_state';

export const createOAuthRouter = (repos?: RepositoryContainer): Router => {
  const router = Router();
  const repositoryContainer = repos || getRepositories();
  const oauthService = new OAuthService(repositoryContainer);

  // Initialize passport strategy if configured
  configurePassport(repositoryContainer);

  // GET /api/auth/google - Initiate OAuth flow with CSRF state protection
  router.get('/google', (req: Request, res: Response, next: NextFunction) => {
    if (!isGoogleOAuthConfigured()) {
      res.status(503).json({
        success: false,
        message: 'Google OAuth is not configured in this environment. Please configure GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.',
      });
      return;
    }

    const state = crypto.randomBytes(16).toString('hex');
    res.cookie(OAUTH_STATE_COOKIE, state, {
      httpOnly: true,
      secure: config.NODE_ENV === 'production',
      maxAge: 10 * 60 * 1000,
      sameSite: 'lax',
    });

    passport.authenticate('google', {
      scope: ['profile', 'email'],
      state,
      session: false,
    })(req, res, next);
  });

  // GET /api/auth/google/callback - Handle OAuth provider callback
  router.get('/google/callback', async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Handle provider cancellation or denial
      if (req.query.error) {
        res.status(400).json({
          success: false,
          message: `OAuth authorization cancelled or denied by provider: ${req.query.error}`,
        });
        return;
      }

      // CSRF State verification
      const stateFromQuery = req.query.state as string;
      const stateFromCookie = req.cookies?.[OAUTH_STATE_COOKIE];

      if (!stateFromQuery || !stateFromCookie || stateFromQuery !== stateFromCookie) {
        res.status(403).json({
          success: false,
          message: 'Invalid OAuth state parameter: CSRF verification failed',
        });
        return;
      }

      res.clearCookie(OAUTH_STATE_COOKIE);

      // Support mock profile in test environment for offline integration testing
      if (config.NODE_ENV === 'test' && req.query.mock_profile) {
        try {
          const profile = JSON.parse(decodeURIComponent(req.query.mock_profile as string)) as GoogleProfileInput;
          const ipAddress = req.ip || req.socket.remoteAddress;
          const userAgent = req.headers['user-agent'];

          const result = await oauthService.handleGoogleProfile(profile, ipAddress, userAgent);
          setRefreshTokenCookie(res, result.refreshToken);

          res.status(200).json({
            success: true,
            message: 'Google authentication successful',
            data: {
              user: result.user,
              accessToken: result.accessToken,
            },
          });
          return;
        } catch (err) {
          return next(err);
        }
      }

      if (!isGoogleOAuthConfigured()) {
        res.status(503).json({
          success: false,
          message: 'Google OAuth is not configured in this environment.',
        });
        return;
      }

      passport.authenticate('google', { session: false }, (err: any, authResult: any) => {
        if (err) {
          return next(err);
        }
        if (!authResult) {
          res.status(401).json({
            success: false,
            message: 'OAuth authentication failed',
          });
          return;
        }

        setRefreshTokenCookie(res, authResult.refreshToken);

        res.status(200).json({
          success: true,
          message: 'Google authentication successful',
          data: {
            user: authResult.user,
            accessToken: authResult.accessToken,
          },
        });
      })(req, res, next);
    } catch (error) {
      next(error);
    }
  });

  return router;
};
