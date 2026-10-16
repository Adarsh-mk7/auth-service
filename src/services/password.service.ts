import { RepositoryContainer } from '../repositories';
import { PasswordUtil } from '../utils/password';
import { TokenUtil } from '../utils/token';
import { config } from '../config/environment';
import { IEmailService, getEmailService } from './email/email.service';
import { BadRequestError, NotFoundError, UnauthorizedError } from '../utils/errors';

export class PasswordService {
  constructor(
    private repos: RepositoryContainer,
    private emailService: IEmailService = getEmailService()
  ) {}

  /**
   * Generates a single-use password reset token if account exists.
   * Returns a generic response to prevent account enumeration.
   */
  async forgotPassword(
    email: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ message: string }> {
    const normalizedEmail = email.trim().toLowerCase();
    const user = await this.repos.users.findByEmail(normalizedEmail);

    if (user) {
      const rawToken = TokenUtil.generateSecureRandomToken(32);
      const tokenHash = TokenUtil.hashToken(rawToken);
      const expiresAt = new Date(
        Date.now() + config.PASSWORD_RESET_TOKEN_EXPIRY_MINUTES * 60 * 1000
      );

      await this.repos.passwordResets.create({
        userId: user.id,
        tokenHash,
        expiresAt,
      });

      await this.emailService.sendPasswordResetEmail(user.email, rawToken, user.name);

      await this.repos.audits.log({
        userId: user.id,
        action: 'PASSWORD_RESET_REQUEST',
        ipAddress: ipAddress ?? null,
        userAgent: userAgent ?? null,
      });
    } else {
      // Audit log attempt for non-existent email
      await this.repos.audits.log({
        action: 'PASSWORD_RESET_REQUEST_UNKNOWN_EMAIL',
        ipAddress: ipAddress ?? null,
        userAgent: userAgent ?? null,
        metadata: { email: normalizedEmail },
      });
    }

    return {
      message: 'If an account with that email exists, password reset instructions have been sent.',
    };
  }

  /**
   * Resets password using a valid, non-expired, single-use reset token.
   * Invalidates all active user sessions upon completion.
   */
  async resetPassword(
    token: string,
    newPassword: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ message: string }> {
    const tokenHash = TokenUtil.hashToken(token);
    const resetRecord = await this.repos.passwordResets.findByTokenHash(tokenHash);

    if (!resetRecord) {
      throw new BadRequestError('Invalid or expired password reset token');
    }

    if (resetRecord.usedAt !== null) {
      throw new BadRequestError('This password reset token has already been used');
    }

    if (resetRecord.expiresAt <= new Date()) {
      throw new BadRequestError('Password reset token has expired');
    }

    const user = await this.repos.users.findById(resetRecord.userId);
    if (!user) {
      throw new NotFoundError('User associated with this reset request was not found');
    }

    // Update password
    const newPasswordHash = await PasswordUtil.hash(newPassword);
    await this.repos.users.update(user.id, { passwordHash: newPasswordHash });

    // Mark reset token as used (single-use enforcement)
    await this.repos.passwordResets.markAsUsed(resetRecord.id);

    // Invalidate all active user sessions for security
    await this.repos.sessions.revokeAllForUser(user.id);

    await this.repos.audits.log({
      userId: user.id,
      action: 'PASSWORD_RESET_SUCCESS',
      ipAddress: ipAddress ?? null,
      userAgent: userAgent ?? null,
    });

    return {
      message: 'Password has been successfully reset. Please log in with your new password.',
    };
  }

  /**
   * Changes password for an authenticated user after verifying current password.
   * Invalidates other active sessions.
   */
  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ message: string }> {
    const user = await this.repos.users.findById(userId);
    if (!user) {
      throw new NotFoundError('User not found');
    }

    if (!user.passwordHash) {
      throw new BadRequestError('This account does not have a local password configured (e.g. OAuth account)');
    }

    const isValidCurrent = await PasswordUtil.compare(currentPassword, user.passwordHash);
    if (!isValidCurrent) {
      await this.repos.audits.log({
        userId: user.id,
        action: 'PASSWORD_CHANGE_FAILURE',
        ipAddress: ipAddress ?? null,
        userAgent: userAgent ?? null,
        metadata: { reason: 'Incorrect current password' },
      });
      throw new UnauthorizedError('Current password is incorrect');
    }

    const newPasswordHash = await PasswordUtil.hash(newPassword);
    await this.repos.users.update(userId, { passwordHash: newPasswordHash });

    // Invalidate existing sessions across other devices
    await this.repos.sessions.revokeAllForUser(userId);

    await this.repos.audits.log({
      userId: user.id,
      action: 'PASSWORD_CHANGE_SUCCESS',
      ipAddress: ipAddress ?? null,
      userAgent: userAgent ?? null,
    });

    return {
      message: 'Password successfully changed. Other active sessions have been revoked.',
    };
  }
}
