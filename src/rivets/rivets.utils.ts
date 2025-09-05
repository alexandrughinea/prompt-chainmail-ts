import { ChainmailContext } from "../types";
import { ThreatLevel } from "./rivets.types";

/**
 * Apply weighted confidence penalty based on threat level
 */
export function applyThreatPenalty(
  context: ChainmailContext,
  level: ThreatLevel
): void {
  context.confidence = Math.max(0, context.confidence - level);
}

/**
 * Common security-related keywords and patterns
 */
export const SECURITY_KEYWORDS = {
  SUSPICIOUS: "ignore|system|instruction|admin|override|execute|eval",
  PRIVILEGED_ROLES: "admin|administrator|system|root|superuser",
  TECHNICAL_ROLES: "developer|programmer|engineer|hacker",
  EXPERT_ROLES: "expert|master|specialist|professional",
  SQL_COMMANDS: "select|insert|update|delete|drop|union|create|alter|truncate",
  CODE_EXECUTION: "eval|exec|execfile|compile|system|popen|shell_exec",
  SYSTEM_COMMANDS: "rm|del|sudo|chmod|chown|kill|ps|ls|cat|whoami|id",
  INSTRUCTION_VERBS:
    "override|ignore|forget|reset|disregard|bypass|disable|enable",
  ROLE_ACTIONS:
    "you\\s+are|act\\s+as|pretend|roleplay|assume|behave\\s+like|simulate|imagine",
  HIJACK_ACTIONS: "reset|clear|replace|modify|change|update|alter",
  HIJACK_TARGETS:
    "instructions|rules|system|memory|behavior|security|safety|protection|mode",
  SYSTEM_MODES: "developer|debug|admin",
} as const;

/**
 * Common regex pattern components
 */
export const PATTERN_COMPONENTS = {
  ARTICLES: "a\\s+|an\\s+|the\\s+",
  OPTIONAL_MODIFIERS: "(.*\\s+)?",
  WORD_BOUNDARY: "\\b",
  WHITESPACE: "\\s+",
  OPTIONAL_WHITESPACE: "\\s*",
} as const;

/**
 * Helper function to create regex patterns with common components
 */
export function createPattern(
  verb: string,
  target: string = "",
  flags: string = "i"
): RegExp {
  const pattern = target
    ? `${verb}\\s+(${PATTERN_COMPONENTS.ARTICLES})?(${PATTERN_COMPONENTS.OPTIONAL_MODIFIERS})?(${target})`
    : verb;
  return new RegExp(pattern, flags);
}

/**
 * Create multiple patterns from a base verb and different targets
 */
export function createPatterns(
  verbs: string[],
  targets: string[],
  flags: string = "i"
): RegExp[] {
  const patterns: RegExp[] = [];
  for (const verb of verbs) {
    for (const target of targets) {
      patterns.push(createPattern(verb, target, flags));
    }
  }
  return patterns;
}

/**
 * Create hijacking patterns by combining actions with targets
 */
export function createHijackPatterns(
  actions: string = SECURITY_KEYWORDS.HIJACK_ACTIONS,
  targets: string = SECURITY_KEYWORDS.HIJACK_TARGETS,
  flags: string = "i"
): RegExp[] {
  return [new RegExp(`(${actions})\\s+(${targets})`, flags)];
}
