/**
 * Threat severity levels for weighted scoring
 */
export enum ThreatLevel {
  LOW = 0.05, // Minor issues (truncation, non-ascii)
  MEDIUM = 0.15, // Moderate threats (role confusion, encoding)
  HIGH = 0.25, // Serious threats (injection patterns, hijacking)
  CRITICAL = 0.4, // Severe threats (code/SQL injection)
}
