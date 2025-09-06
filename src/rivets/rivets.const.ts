/**
 * Common security-related keywords and patterns
 */
export const SECURITY_COMPONENTS = {
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
    "you\\s+are|act\\s+as|roleplay|assume|behave\\s+like|simulate|imagine|dream|pretend",
  ROLE_CHANGE:
    "be\\s+(a|an|the)\\s+(admin|administrator|system|root|superuser|developer|programmer|engineer|hacker|expert|master|specialist|professional)",
  HIJACK_ACTIONS: "reset|clear|replace|modify|change|update|alter",
  HIJACK_TARGETS:
    "instructions|rules|system|memory|behavior|security|safety|protection|mode",
  SYSTEM_MODES: "developer|debug|admin|test|sandbox|production|staging",

  TEMPORAL_MODIFIERS:
    "previous|prior|all|now|above|current|past|upcoming|earlier",

  INSTRUCTION_TARGETS:
    "instruction|rule|prompt|system|directive|reset|memorize|config|policy|guideline|command|training|programming|conditioning",

  INFORMATION_VERBS:
    "tell|show|give|reveal|expose|display|list|explain|describe|report",

  QUESTION_WORDS: "what|show|which|how|why|when",

  POSSESSIVE_PRONOUNS: "your|the|me|my|our|mine|their",

  BYPASS_TERMS:
    "jailbreak|prison\\s+break|bypass|exploit|workaround|unlock|escape",

  SECURITY_TARGETS:
    "security|safety|filter|protection|guard|defense|firewall|shield",

  RESTART_ACTIONS: "start|begin|restart|reinitialize|reboot|launch",

  RESTART_MODIFIERS: "over|again|fresh|anew|from scratch|once more|reset",

  EVERYTHING_TERMS: "everything|all|entire|whole|total|complete",

  ARTICLES: "a|an|the|this|that|these|those",

  OVERRIDE_VERBS: "override|bypass|reset|overrule|supersede|nullify|invalidate",

  REVEAL_VERBS: "reveal|expose|display|uncover|unveil|disclose|showcase",

  FORGET_VERBS: "forget|ignore|discard|erase|delete|omit|drop",

  NEW_MODIFIERS: "new|latest|recent|updated|modern|fresh|novel",

  HIJACK_PATTERNS: "hijack|takeover|commandeer|seize|capture|control",

  CONTEXT_MODIFIERS: "context|conversation|chat|session|dialogue|interaction",

  EXECUTION_VERBS: "execute|run|perform|process|handle|trigger|activate",

  NEGATION_TERMS: "don't|do not|never|stop|cease|halt|end|terminate",

  CONDITIONAL_TERMS: "if|when|unless|provided|given|assuming|suppose",

  PRIORITY_TERMS: "priority|urgent|critical|important|essential|vital",
} as const;

/**
 * Role indicators for detecting role confusion attacks
 */
export const ROLE_INDICATORS = "system:|assistant:|user:|human:|ai:" as const;

/**
 * Common regex pattern components
 */
export const PATTERN_COMPONENTS = {
  ARTICLES: "a\\s+|an\\s+|the\\s+",
  OPTIONAL_MODIFIERS: "(.*\\s+)?",
  WORD_BOUNDARY: "\\b",
  WHITESPACE: "\\s+",
  OPTIONAL_WHITESPACE: "\\s*",
  OPTIONAL_ARTICLES: "(a|an|the)?",
  PLURAL_SUFFIX: "s?",
  QUESTION_SUFFIX: "\\?",
} as const;
