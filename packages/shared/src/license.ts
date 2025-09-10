import { createHmac, timingSafeEqual } from "crypto";

interface JWTHeader {
  alg: string;
  typ: string;
}

interface JWTPayload {
  iss: string; // issuer
  sub: string; // subject (license type)
  exp: number; // expiration
  iat: number; // issued at
  tier: "pro" | "enterprise";
  features?: string[];
}

function base64urlDecode(str: string): string {
  str += "=".repeat((4 - (str.length % 4)) % 4);
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(str, "base64").toString("utf8");
}

function base64urlEncode(str: string): string {
  return Buffer.from(str)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function verifySignature(
  data: string,
  signature: string,
  secret: string
): boolean {
  const expectedSignature = createHmac("sha256", secret)
    .update(data)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  if (signature.length !== expectedSignature.length) {
    return false;
  }

  return timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}

/**
 * Parse and validate JWT with signature verification
 */
function parseAndValidateJWT(token: string, secret: string): JWTPayload {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format");
  }

  const [headerB64, payloadB64, signatureB64] = parts;
  const data = `${headerB64}.${payloadB64}`;

  if (!verifySignature(data, signatureB64, secret)) {
    throw new Error("Invalid JWT signature");
  }

  try {
    const header = JSON.parse(base64urlDecode(headerB64)) as JWTHeader;
    if (header.alg !== "HS256") {
      throw new Error("Unsupported JWT algorithm");
    }
    const payload = JSON.parse(base64urlDecode(payloadB64)) as JWTPayload;
    return payload;
  } catch (error) {
    if (error instanceof Error && error.message.includes("JWT")) {
      throw error;
    }
    throw new Error("Invalid JWT payload");
  }
}

export function validateLicense(
  envVarName: string,
  expectedTier: "pro" | "enterprise",
  secret: string
): boolean {
  const LICENSE_JWT = process.env[envVarName];

  if (!LICENSE_JWT) {
    throw new Error(`${envVarName} environment variable required`);
  }

  try {
    const payload = parseAndValidateJWT(LICENSE_JWT, secret);

    if (payload.iss !== "prompt-chainmail.com") {
      throw new Error("Invalid license issuer");
    }

    if (payload.tier !== expectedTier) {
      throw new Error(`Invalid license tier for ${expectedTier} package`);
    }

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      throw new Error("License has expired");
    }

    const tierCapitalized =
      expectedTier.charAt(0).toUpperCase() + expectedTier.slice(1);
    console.log(
      `✅ ${tierCapitalized} license validated - expires: ${new Date(payload.exp * 1000).toISOString()}`
    );
    return true;
  } catch (error) {
    throw new Error(
      `License validation failed: ${error instanceof Error ? error.message : "Unknown error"}`
    );
  }
}

/**
 * Generate a JWT for testing (development only)
 */
export function generateTestJWT(
  tier: "pro" | "enterprise",
  secret: string,
  expiresInSeconds = 365 * 24 * 60 * 60 // 1 year
): string {
  const header = {
    alg: "HS256",
    typ: "JWT",
  };

  const payload = {
    iss: "prompt-chainmail.com",
    sub: `${tier}-license`,
    tier,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + expiresInSeconds,
  };

  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(payload));
  const data = `${headerB64}.${payloadB64}`;

  const signature = createHmac("sha256", secret)
    .update(data)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  return `${data}.${signature}`;
}
