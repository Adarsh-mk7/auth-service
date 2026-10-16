import { config } from '../../config/environment';

export interface SentEmail {
  to: string;
  subject: string;
  body: string;
  token?: string;
  sentAt: Date;
}

export interface IEmailService {
  sendPasswordResetEmail(to: string, resetToken: string, name: string): Promise<void>;
}

export class DevelopmentEmailService implements IEmailService {
  private sentEmails: SentEmail[] = [];

  async sendPasswordResetEmail(to: string, resetToken: string, name: string): Promise<void> {
    const resetUrl = `${config.FRONTEND_URL}/reset-password?token=${resetToken}`;
    const email: SentEmail = {
      to,
      subject: 'Password Reset Request',
      body: `Hello ${name},\n\nYou requested a password reset. Use this link within ${config.PASSWORD_RESET_TOKEN_EXPIRY_MINUTES} minutes: ${resetUrl}`,
      token: resetToken,
      sentAt: new Date(),
    };

    this.sentEmails.push(email);

    if (config.NODE_ENV === 'development') {
      console.log(`[EmailService:DEV] Password reset email sent to ${to}. Reset URL: ${resetUrl}`);
    }
  }

  getSentEmails(): SentEmail[] {
    return [...this.sentEmails];
  }

  clear(): void {
    this.sentEmails = [];
  }
}

let activeEmailService: IEmailService = new DevelopmentEmailService();

export const getEmailService = (): IEmailService => {
  return activeEmailService;
};

export const setEmailService = (service: IEmailService): void => {
  activeEmailService = service;
};
