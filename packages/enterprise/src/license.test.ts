import { describe, it, expect, beforeEach, afterAll, vi } from 'vitest';
import { validateEnterpriseLicense } from './license';
import { generateTestJWT } from '../../shared/src/license';

describe('Enterprise License Validation', () => {
  const originalEnv = process.env;
  const testSecret = 'test-secret-key-for-validation';

  beforeEach(() => {
    vi.resetModules();
    process.env = { ...originalEnv };
    process.env.PROMPT_CHAINMAIL_SECRET = testSecret;
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it('should throw error when no license is provided', () => {
    delete process.env.PROMPT_CHAINMAIL_ENTERPRISE_LICENSE;
    expect(() => validateEnterpriseLicense()).toThrow('PROMPT_CHAINMAIL_ENTERPRISE_LICENSE environment variable required');
  });

  it('should throw error for invalid JWT format', () => {
    process.env.PROMPT_CHAINMAIL_ENTERPRISE_LICENSE = 'invalid-jwt';
    expect(() => validateEnterpriseLicense()).toThrow('License validation failed: Invalid JWT format');
  });

  it('should throw error for invalid signature', () => {
    // Valid JWT structure but wrong signature
    const invalidJWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJwcm9tcHQtY2hhaW5tYWlsLmNvbSIsInRpZXIiOiJlbnRlcnByaXNlIiwiZXhwIjo5OTk5OTk5OTk5fQ.wrong-signature';
    process.env.PROMPT_CHAINMAIL_ENTERPRISE_LICENSE = invalidJWT;
    expect(() => validateEnterpriseLicense()).toThrow('License validation failed: Invalid JWT signature');
  });

  it('should throw error for wrong tier', () => {
    const proJWT = generateTestJWT('pro', testSecret);
    process.env.PROMPT_CHAINMAIL_ENTERPRISE_LICENSE = proJWT;
    expect(() => validateEnterpriseLicense()).toThrow('License validation failed: Invalid license tier for enterprise package');
  });

  it('should throw error for expired license', () => {
    const expiredJWT = generateTestJWT('enterprise', testSecret, -3600); // Expired 1 hour ago
    process.env.PROMPT_CHAINMAIL_ENTERPRISE_LICENSE = expiredJWT;
    expect(() => validateEnterpriseLicense()).toThrow('License validation failed: License has expired');
  });

  it('should validate correct enterprise license', () => {
    const validJWT = generateTestJWT('enterprise', testSecret);
    process.env.PROMPT_CHAINMAIL_ENTERPRISE_LICENSE = validJWT;
    
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    expect(validateEnterpriseLicense()).toBe(true);
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('✅ Enterprise license validated'));
    consoleSpy.mockRestore();
  });
});
