import { Response, CookieOptions } from 'express';
import { config } from '../config/environment';

export const REFRESH_TOKEN_COOKIE_NAME = 'refresh_token';

export const getRefreshTokenCookieOptions = (): CookieOptions => {
  const isProd = config.NODE_ENV === 'production' || config.COOKIE_SECURE;
  return {
    httpOnly: true,
    secure: isProd,
    sameSite: config.COOKIE_SAME_SITE as 'lax' | 'strict' | 'none',
    maxAge: config.JWT_REFRESH_EXPIRY_DAYS * 24 * 60 * 60 * 1000,
    path: '/api/auth',
  };
};

export const setRefreshTokenCookie = (res: Response, token: string): void => {
  res.cookie(REFRESH_TOKEN_COOKIE_NAME, token, getRefreshTokenCookieOptions());
};

export const clearRefreshTokenCookie = (res: Response): void => {
  res.clearCookie(REFRESH_TOKEN_COOKIE_NAME, {
    httpOnly: true,
    secure: config.NODE_ENV === 'production' || config.COOKIE_SECURE,
    sameSite: config.COOKIE_SAME_SITE as 'lax' | 'strict' | 'none',
    path: '/api/auth',
  });
};
