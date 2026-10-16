import { describe, it, expect } from 'vitest';
import { PasswordUtil } from '../../src/utils/password';

describe('Password Utility', () => {
  it('hashes passwords and verifies matching plaintext correctly', async () => {
    const plaintext = 'SecurePass123!@#';
    const hash = await PasswordUtil.hash(plaintext);

    expect(hash).not.toBe(plaintext);
    expect(hash.startsWith('$2')).toBe(true);

    const isMatch = await PasswordUtil.compare(plaintext, hash);
    expect(isMatch).toBe(true);
  });

  it('rejects incorrect passwords against the hash', async () => {
    const plaintext = 'SecurePass123!@#';
    const hash = await PasswordUtil.hash(plaintext);

    const isMatch = await PasswordUtil.compare('WrongPassword456$', hash);
    expect(isMatch).toBe(false);
  });

  it('generates distinct salts for identical passwords', async () => {
    const plaintext = 'IdenticalPassword1!';
    const hash1 = await PasswordUtil.hash(plaintext);
    const hash2 = await PasswordUtil.hash(plaintext);

    expect(hash1).not.toBe(hash2);
    expect(await PasswordUtil.compare(plaintext, hash1)).toBe(true);
    expect(await PasswordUtil.compare(plaintext, hash2)).toBe(true);
  });
});
