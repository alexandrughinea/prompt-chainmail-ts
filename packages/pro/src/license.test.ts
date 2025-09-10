/**
 * Tests for Pro JWT license validation with signature verification
 */

import { describe, it, expect, beforeEach, afterAll, vi } from "vitest";
import { validateProLicense } from "./license";
import { generateTestJWT } from "../../shared/src/license";

describe("Pro License Validation", () => {
  const originalEnv = process.env;
  const testSecret = "test-secret-key-for-validation";

  beforeEach(() => {
    vi.resetModules();
    process.env = { ...originalEnv };
    process.env.PROMPT_CHAINMAIL_SECRET = testSecret;
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it("should throw error when no license is provided", () => {
    delete process.env.PROMPT_CHAINMAIL_PRO_LICENSE;
    expect(() => validateProLicense()).toThrow(
      "PROMPT_CHAINMAIL_PRO_LICENSE environment variable required"
    );
  });

  it("should throw error for invalid JWT format", () => {
    process.env.PROMPT_CHAINMAIL_PRO_LICENSE = "invalid-jwt";
    expect(() => validateProLicense()).toThrow(
      "License validation failed: Invalid JWT format"
    );
  });

  it("should throw error for invalid signature", () => {
    // Valid JWT structure but wrong signature
    const invalidJWT =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJwcm9tcHQtY2hhaW5tYWlsLmNvbSIsInRpZXIiOiJwcm8iLCJleHAiOjk5OTk5OTk5OTl9.wrong-signature";
    process.env.PROMPT_CHAINMAIL_PRO_LICENSE = invalidJWT;
    expect(() => validateProLicense()).toThrow(
      "License validation failed: Invalid JWT signature"
    );
  });

  it("should throw error for wrong tier", () => {
    const enterpriseJWT = generateTestJWT("enterprise", testSecret);
    process.env.PROMPT_CHAINMAIL_PRO_LICENSE = enterpriseJWT;
    expect(() => validateProLicense()).toThrow(
      "License validation failed: Invalid license tier for pro package"
    );
  });

  it("should throw error for expired license", () => {
    const expiredJWT = generateTestJWT("pro", testSecret, -3600); // Expired 1 hour ago
    process.env.PROMPT_CHAINMAIL_PRO_LICENSE = expiredJWT;
    expect(() => validateProLicense()).toThrow(
      "License validation failed: License has expired"
    );
  });

  it("should validate correct pro license", () => {
    const validJWT = generateTestJWT("pro", testSecret);
    process.env.PROMPT_CHAINMAIL_PRO_LICENSE = validJWT;

    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    expect(validateProLicense()).toBe(true);
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("✅ Pro license validated")
    );
    consoleSpy.mockRestore();
  });
});
