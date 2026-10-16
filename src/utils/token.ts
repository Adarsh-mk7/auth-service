import jwt, { SignOptions, VerifyOptions } from 'jsonwebtoken';
import crypto from 'crypto';
import { config } from '../config/environment';
import { UserContext } from '../types';
import { UnauthorizedError } from './errors';

export class TokenUtil {
  /**
   * Signs a short-lived access JWT for the authenticated user with a unique jwtid (jti).
   */
  static signAccessToken(user: UserContext): string {
    const payload: UserContext = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
    };

    const options: SignOptions = {
      expiresIn: config.JWT_ACCESS_EXPIRY as any,
      issuer: config.JWT_ISSUER,
      audience: config.JWT_AUDIENCE,
      jwtid: crypto.randomUUID(),
    };

    return jwt.sign(payload, config.JWT_ACCESS_SECRET, options);
  }

  /**
   * Verifies and decodes an access JWT.
   */
  static verifyAccessToken(token: string): UserContext {
    try {
      const options: VerifyOptions = {
        issuer: config.JWT_ISSUER,
        audience: config.JWT_AUDIENCE,
      };

      const decoded = jwt.verify(token, config.JWT_ACCESS_SECRET, options) as UserContext;
      return decoded;
    } catch (error: any) {
      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedError('Access token has expired');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new UnauthorizedError('Invalid access token');
      }
      throw new UnauthorizedError('Authentication failed');
    }
  }

  /**
   * Generates a cryptographically secure random token string for refresh tokens and reset tokens.
   */
  static generateSecureRandomToken(byteLength = 32): string {
    return crypto.randomBytes(byteLength).toString('hex');
  }

  /**
   * Generates a deterministic SHA-256 hash of a token for secure database storage.
   */
  static hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }
}
