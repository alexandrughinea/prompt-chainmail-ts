import { ChainmailContext } from "../types";
import { ThreatLevel } from "./rivets.types";
import { SECURITY_COMPONENTS, PATTERN_COMPONENTS } from "./rivets.const";
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
 * Helper function to create regex patterns with common components
 */
export function createRolePattern(
  verb: string,
  target: string = "",
  flags: string = "i"
): RegExp {
  const roles = `${SECURITY_COMPONENTS.PRIVILEGED_ROLES}|${SECURITY_COMPONENTS.TECHNICAL_ROLES}|${SECURITY_COMPONENTS.EXPERT_ROLES}`;
  const pattern = target
    ? `${verb}\\s+(${PATTERN_COMPONENTS.ARTICLES})?(${PATTERN_COMPONENTS.OPTIONAL_MODIFIERS})?(${roles})`
    : verb;
  return new RegExp(pattern, flags);
}

/**
 * Create pattern detection patterns using extracted keywords
 */
export function createPatternDetectionPatterns(): RegExp[] {
  return [
    // Ignore/forget patterns with temporal modifiers - classic injection pattern
    new RegExp(
      `(${SECURITY_COMPONENTS.FORGET_VERBS})${PATTERN_COMPONENTS.WHITESPACE}(${SECURITY_COMPONENTS.TEMPORAL_MODIFIERS})${PATTERN_COMPONENTS.WHITESPACE}(${SECURITY_COMPONENTS.INSTRUCTION_TARGETS})${PATTERN_COMPONENTS.PLURAL_SUFFIX}`,
      "i"
    ),

    // Role assumption patterns
    new RegExp(
      `(${SECURITY_COMPONENTS.ROLE_ACTIONS}).*?(${SECURITY_COMPONENTS.PRIVILEGED_ROLES}|${SECURITY_COMPONENTS.TECHNICAL_ROLES})`,
      "i"
    ),

    // System mode activation
    new RegExp(
      `(${SECURITY_COMPONENTS.TECHNICAL_ROLES})${PATTERN_COMPONENTS.WHITESPACE}mode`,
      "i"
    ),

    // Forget everything patterns - must include "above" or "previous" with instructions
    new RegExp(
      `(${SECURITY_COMPONENTS.FORGET_VERBS})${PATTERN_COMPONENTS.WHITESPACE}(${SECURITY_COMPONENTS.EVERYTHING_TERMS})${PATTERN_COMPONENTS.WHITESPACE}(${SECURITY_COMPONENTS.TEMPORAL_MODIFIERS})${PATTERN_COMPONENTS.WHITESPACE}and${PATTERN_COMPONENTS.WHITESPACE}(${SECURITY_COMPONENTS.ROLE_ACTIONS})`,
      "i"
    ),

    // New instruction patterns - must be explicit system instructions
    new RegExp(
      `${PATTERN_COMPONENTS.WORD_BOUNDARY}new${PATTERN_COMPONENTS.WHITESPACE}(system${PATTERN_COMPONENTS.WHITESPACE})?(${SECURITY_COMPONENTS.INSTRUCTION_TARGETS}):${PATTERN_COMPONENTS.WHITESPACE}you${PATTERN_COMPONENTS.WHITESPACE}must`,
      "i"
    ),

    // Override security patterns - more specific
    new RegExp(
      `(${SECURITY_COMPONENTS.OVERRIDE_VERBS})${PATTERN_COMPONENTS.WHITESPACE}(system${PATTERN_COMPONENTS.WHITESPACE})?(${SECURITY_COMPONENTS.INSTRUCTION_TARGETS}|${SECURITY_COMPONENTS.SECURITY_TARGETS})`,
      "i"
    ),

    // Bypass terms
    new RegExp(SECURITY_COMPONENTS.BYPASS_TERMS, "i"),

    // Role transformation patterns
    new RegExp(
      `you${PATTERN_COMPONENTS.WHITESPACE}are${PATTERN_COMPONENTS.WHITESPACE}now${PATTERN_COMPONENTS.WHITESPACE}(${SECURITY_COMPONENTS.ARTICLES})`,
      "i"
    ),

    // Information extraction patterns - very specific system queries
    new RegExp(
      `(${SECURITY_COMPONENTS.INFORMATION_VERBS})${PATTERN_COMPONENTS.WHITESPACE}me${PATTERN_COMPONENTS.WHITESPACE}(${SECURITY_COMPONENTS.POSSESSIVE_PRONOUNS})${PATTERN_COMPONENTS.WHITESPACE}(exact${PATTERN_COMPONENTS.WHITESPACE})?(system|prompt)${PATTERN_COMPONENTS.WHITESPACE}(${SECURITY_COMPONENTS.INSTRUCTION_TARGETS})${PATTERN_COMPONENTS.PLURAL_SUFFIX}(?!${PATTERN_COMPONENTS.WHITESPACE}for)`,
      "i"
    ),

    // Question patterns about instructions - only direct system queries with context
    new RegExp(
      `what\\s+(are|is)\\s+(${SECURITY_COMPONENTS.POSSESSIVE_PRONOUNS})\\s+(exact\\s+)?(system\\s+)?(${SECURITY_COMPONENTS.INSTRUCTION_TARGETS})s?\\s+(you\\s+follow|given|received|that\\s+govern)`,
      "i"
    ),

    // Direct instruction queries - must be about system instructions specifically
    new RegExp(
      `what\\s+are\\s+(${SECURITY_COMPONENTS.POSSESSIVE_PRONOUNS})\\s+(system\\s+)?(${SECURITY_COMPONENTS.INSTRUCTION_TARGETS})s?\\s+(you\\s+follow|that\\s+govern)`,
      "i"
    ),

    // Reveal/expose patterns - must be about system instructions
    new RegExp(
      `(${SECURITY_COMPONENTS.REVEAL_VERBS})\\s+(${SECURITY_COMPONENTS.POSSESSIVE_PRONOUNS})\\s+(system\\s+)?(${SECURITY_COMPONENTS.INSTRUCTION_TARGETS})s?`,
      "i"
    ),

    // Bypass security patterns
    new RegExp(
      `${SECURITY_COMPONENTS.OVERRIDE_VERBS}\\s+(${SECURITY_COMPONENTS.SECURITY_TARGETS})`,
      "i"
    ),

    // Restart patterns
    new RegExp(
      `(${SECURITY_COMPONENTS.RESTART_ACTIONS})\\s+(${SECURITY_COMPONENTS.RESTART_MODIFIERS})`,
      "i"
    ),

    // Reset patterns - must be explicit system resets
    new RegExp(
      `${SECURITY_COMPONENTS.OVERRIDE_VERBS}\\s+(system|all)\\s+(${SECURITY_COMPONENTS.INSTRUCTION_TARGETS})s?`,
      "i"
    ),
  ];
}
