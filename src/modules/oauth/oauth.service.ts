import { RepositoryContainer } from '../../repositories';
import { TokenUtil } from '../../utils/token';
import { config } from '../../config/environment';
import { ConflictError, BadRequestError } from '../../utils/errors';
import { sanitizeUser, AuthSuccessDto } from '../../services/auth.service';
import { Role, User } from '@prisma/client';
import crypto from 'crypto';

export interface GoogleProfileInput {
  id: string;
  email: string;
  name: string;
  isEmailVerified: boolean;
}

export class OAuthService {
  constructor(private repos: RepositoryContainer) {}

  /**
   * Processes a Google OAuth sign-in profile following a safe account-linking policy:
   * 1. Reject unverified OAuth emails.
   * 2. If OAuth account already linked -> log in.
   * 3. If user exists with verified email -> safely link OAuth account and log in.
   * 4. If user exists with unverified email -> reject auto-linking to prevent account takeover.
   * 5. If user does not exist -> create user with verified email, link OAuth account, and log in.
   */
  async handleGoogleProfile(
    profile: GoogleProfileInput,
    ipAddress?: string,
    userAgent?: string
  ): Promise<AuthSuccessDto> {
    const { id: providerUserId, name } = profile;
    const email = profile.email.trim().toLowerCase();

    // Enforce verified email from OAuth provider
    if (!profile.isEmailVerified) {
      throw new BadRequestError('Google account email is not verified by Google');
    }

    // 1. Check if OAuth association already exists
    const existingOAuth = await this.repos.oauthAccounts.findByProvider('google', providerUserId);
    if (existingOAuth && existingOAuth.user) {
      const user = existingOAuth.user;

      // Issue tokens
      const rawRefreshToken = TokenUtil.generateSecureRandomToken();
      const tokenHash = TokenUtil.hashToken(rawRefreshToken);
      const familyId = crypto.randomUUID();
      const expiresAt = new Date(Date.now() + config.JWT_REFRESH_EXPIRY_DAYS * 24 * 60 * 60 * 1000);

      await this.repos.sessions.create({
        userId: user.id,
        tokenHash,
        familyId,
        generation: 1,
        expiresAt,
        ipAddress: ipAddress ?? null,
        userAgent: userAgent ?? null,
      });

      const sanitized = sanitizeUser(user);
      const accessToken = TokenUtil.signAccessToken(sanitized);

      await this.repos.audits.log({
        userId: user.id,
        action: 'OAUTH_LOGIN',
        ipAddress: ipAddress ?? null,
        userAgent: userAgent ?? null,
        metadata: { provider: 'google', providerUserId },
      });

      return {
        user: sanitized,
        accessToken,
        refreshToken: rawRefreshToken,
      };
    }

    // 2. Check if user with this email already exists
    const existingUser = await this.repos.users.findByEmail(email);

    let targetUser: User;

    if (existingUser) {
      // Rejection of unverified local account to prevent account takeover
      if (!existingUser.isEmailVerified) {
        throw new ConflictError(
          'An account with this email address already exists but has not been verified. Please verify your email before linking Google OAuth.'
        );
      }

      // Safely link OAuth account to verified existing user
      await this.repos.oauthAccounts.create({
        userId: existingUser.id,
        provider: 'google',
        providerUserId,
      });

      await this.repos.audits.log({
        userId: existingUser.id,
        action: 'OAUTH_ACCOUNT_LINKED',
        ipAddress: ipAddress ?? null,
        userAgent: userAgent ?? null,
        metadata: { provider: 'google', providerUserId },
      });

      targetUser = existingUser;
    } else {
      // 3. Create new user with verified email
      targetUser = await this.repos.users.create({
        email,
        name: name || 'Google User',
        passwordHash: null,
        role: Role.USER,
        isEmailVerified: true,
      });

      await this.repos.oauthAccounts.create({
        userId: targetUser.id,
        provider: 'google',
        providerUserId,
      });

      await this.repos.audits.log({
        userId: targetUser.id,
        action: 'OAUTH_REGISTER',
        ipAddress: ipAddress ?? null,
        userAgent: userAgent ?? null,
        metadata: { provider: 'google', providerUserId },
      });
    }

    // Issue application tokens
    const rawRefreshToken = TokenUtil.generateSecureRandomToken();
    const tokenHash = TokenUtil.hashToken(rawRefreshToken);
    const familyId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + config.JWT_REFRESH_EXPIRY_DAYS * 24 * 60 * 60 * 1000);

    await this.repos.sessions.create({
      userId: targetUser.id,
      tokenHash,
      familyId,
      generation: 1,
      expiresAt,
      ipAddress: ipAddress ?? null,
      userAgent: userAgent ?? null,
    });

    const sanitized = sanitizeUser(targetUser);
    const accessToken = TokenUtil.signAccessToken(sanitized);

    return {
      user: sanitized,
      accessToken,
      refreshToken: rawRefreshToken,
    };
  }
}
