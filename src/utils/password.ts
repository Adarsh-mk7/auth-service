import bcrypt from 'bcryptjs';
import { config } from '../config/environment';

export class PasswordUtil {
  /**
   * Hashes a plaintext password using bcrypt with configurable work factor.
   * Uses 4 rounds in test environment for fast test execution, or BCRYPT_SALT_ROUNDS in dev/prod.
   */
  static async hash(password: string): Promise<string> {
    const rounds = config.NODE_ENV === 'test' ? 4 : config.BCRYPT_SALT_ROUNDS;
    const salt = await bcrypt.genSalt(rounds);
    return bcrypt.hash(password, salt);
  }

  /**
   * Securely compares plaintext password against bcrypt hash.
   */
  static async compare(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }
}
