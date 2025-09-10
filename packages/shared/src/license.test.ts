/**
 * Tests for shared JWT license validation with signature verification
 */

import { describe, it, expect, beforeEach, afterAll, vi } from "vitest";
import { validateLicense, generateTestJWT } from "./license";

describe("Shared License Validation", () => {
  const originalEnv = process.env;
  const testSecret = "test-secret-key-for-validation";

  beforeEach(() => {
    vi.resetModules();
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it("should throw error when no license is provided", () => {
    expect(() => validateLicense("MISSING_ENV_VAR", "pro", testSecret)).toThrow(
      "MISSING_ENV_VAR environment variable required"
    );
  });

  it("should throw error for invalid JWT format", () => {
    process.env.TEST_LICENSE = "invalid-jwt";
    expect(() => validateLicense("TEST_LICENSE", "pro", testSecret)).toThrow(
      "License validation failed: Invalid JWT format"
    );
  });

  it("should throw error for invalid signature", () => {
    // Valid JWT structure but wrong signature
    const invalidJWT =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJwcm9tcHQtY2hhaW5tYWlsLmNvbSIsInRpZXIiOiJwcm8iLCJleHAiOjk5OTk5OTk5OTl9.wrong-signature";
    process.env.TEST_LICENSE = invalidJWT;
    expect(() => validateLicense("TEST_LICENSE", "pro", testSecret)).toThrow(
      "License validation failed: Invalid JWT signature"
    );
  });

  it("should throw error for wrong issuer", () => {
    const wrongIssuerJWT = generateTestJWT("pro", testSecret);
    // Manually create JWT with wrong issuer
    const header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; // {"alg":"HS256","typ":"JWT"}
    const payload =
      "eyJpc3MiOiJ3cm9uZy5jb20iLCJ0aWVyIjoicHJvIiwiZXhwIjo5OTk5OTk5OTk5fQ"; // {"iss":"wrong.com","tier":"pro","exp":9999999999}

    // Generate proper signature for wrong payload
    const crypto = require("crypto");
    const data = `${header}.${payload}`;
    const signature = crypto
      .createHmac("sha256", testSecret)
      .update(data)
      .digest("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");

    process.env.TEST_LICENSE = `${data}.${signature}`;
    expect(() => validateLicense("TEST_LICENSE", "pro", testSecret)).toThrow(
      "License validation failed: Invalid license issuer"
    );
  });

  it("should throw error for wrong tier", () => {
    const proJWT = generateTestJWT("pro", testSecret);
    process.env.TEST_LICENSE = proJWT;
    expect(() =>
      validateLicense("TEST_LICENSE", "enterprise", testSecret)
    ).toThrow(
      "License validation failed: Invalid license tier for enterprise package"
    );
  });

  it("should throw error for expired license", () => {
    const expiredJWT = generateTestJWT("pro", testSecret, -3600); // Expired 1 hour ago
    process.env.TEST_LICENSE = expiredJWT;
    expect(() => validateLicense("TEST_LICENSE", "pro", testSecret)).toThrow(
      "License validation failed: License has expired"
    );
  });

  it("should validate correct pro license", () => {
    const validJWT = generateTestJWT("pro", testSecret);
    process.env.TEST_LICENSE = validJWT;

    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    expect(validateLicense("TEST_LICENSE", "pro", testSecret)).toBe(true);
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("✅ Pro license validated")
    );
    consoleSpy.mockRestore();
  });

  it("should validate correct enterprise license", () => {
    const validJWT = generateTestJWT("enterprise", testSecret);
    process.env.TEST_LICENSE = validJWT;

    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    expect(validateLicense("TEST_LICENSE", "enterprise", testSecret)).toBe(
      true
    );
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("✅ Enterprise license validated")
    );
    consoleSpy.mockRestore();
  });

  describe("generateTestJWT", () => {
    it("should generate valid JWT for pro tier", () => {
      const jwt = generateTestJWT("pro", testSecret);
      expect(jwt.split(".")).toHaveLength(3);

      process.env.TEST_LICENSE = jwt;
      expect(validateLicense("TEST_LICENSE", "pro", testSecret)).toBe(true);
    });

    it("should generate valid JWT for enterprise tier", () => {
      const jwt = generateTestJWT("enterprise", testSecret);
      expect(jwt.split(".")).toHaveLength(3);

      process.env.TEST_LICENSE = jwt;
      expect(validateLicense("TEST_LICENSE", "enterprise", testSecret)).toBe(
        true
      );
    });
  });
});
