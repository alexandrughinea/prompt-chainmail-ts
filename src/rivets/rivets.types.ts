export enum SupportedLanguages {
  EN, // English
  FR, // French
  DE, // Deutsch
  ES, // Spanish
  IT, // Italian
  JA, // Japanese
  KO, // Korean
  PT, // Portuguese
  RU, // Russian
  ZH, // Chinese
  AR, // Arabic
  UK, // Ukrainian
  RO, // Romanian
  HI, // Hindi
  FA, // Persian/Farsi
  BE, // Belarusian
  HE, // Hebrew
  PL, // Polish
  NL, // Dutch
  LV, // Latvian
}
/**
 * Threat levels for security violations
 */
export enum ThreatLevel {
  LOW = 0.1,
  MEDIUM = 0.25,
  HIGH = 0.4,
  CRITICAL = 0.6,
}

/**
 * Standard security flags used by default rivets
 */
export enum SecurityFlag {
  // Content processing flags
  TRUNCATED = "truncated",
  INJECTION_PATTERN = "injection_pattern",

  // Role confusion flags
  ROLE_CONFUSION = "role_confusion",
  ROLE_CONFUSION_LOOKALIKE_CHARACTERS = "role_confusion_lookalike_characters",
  ROLE_CONFUSION_MULTILINGUAL_ATTACK = "role_confusion_multilingual_attack",
  ROLE_CONFUSION_HIGH_RISK_ROLE_CONFUSION = "high_risk_role_confusion",

  // Encoding detection flags
  BASE64_ENCODING = "base64_encoding",
  HEX_ENCODING = "hex_encoding",
  URL_ENCODING = "url_encoding",
  UNICODE_ENCODING = "unicode_encoding",
  HTML_ENTITY_ENCODING = "html_entity_encoding",
  BINARY_ENCODING = "binary_encoding",
  OCTAL_ENCODING = "octal_encoding",
  ROT13_ENCODING = "rot13_encoding",
  MIXED_CASE_OBFUSCATION = "mixed_case_obfuscation",

  // Structure analysis flags
  EXCESSIVE_LINES = "excessive_lines",
  NON_ASCII_HEAVY = "non_ascii_heavy",
  REPETITIVE_CONTENT = "repetitive_content",

  // Confidence and rate limiting flags
  CONFIDENCE_RANGE = "confidence_range",
  LOW_CONFIDENCE = "low_confidence",
  RATE_LIMITED = "rate_limited",

  // Injection detection flags
  SQL_INJECTION = "sql_injection",
  CODE_INJECTION = "code_injection",
  TEMPLATE_INJECTION = "template_injection",

  // Attack pattern flags
  DELIMITER_CONFUSION = "delimiter_confusion",
  INSTRUCTION_HIJACKING = "instruction_hijacking",
  MULTILINGUAL_ATTACK = "multilingual_attack",
  HIGH_RISK_LANGUAGE = "high_risk_language",

  // Role confusion attack types
  ROLE_CONFUSION_ROLE_ASSUMPTION = "role_confusion_role_assumption",
  ROLE_CONFUSION_MODE_SWITCHING = "role_confusion_mode_switching",
  ROLE_CONFUSION_PERMISSION_ASSERTION = "role_confusion_permission_assertion",
  ROLE_CONFUSION_SCRIPT_MIXING = "role_confusion_script_mixing",

  // Instruction hijacking attack types
  INSTRUCTION_HIJACKING_OVERRIDE = "instruction_hijacking_override",
  INSTRUCTION_HIJACKING_IGNORE = "instruction_hijacking_ignore",
  INSTRUCTION_HIJACKING_RESET = "instruction_hijacking_reset",
  INSTRUCTION_HIJACKING_BYPASS = "instruction_hijacking_bypass",
  INSTRUCTION_HIJACKING_REVEAL = "instruction_hijacking_reveal",
  INSTRUCTION_HIJACKING_SCRIPT_MIXING = "instruction_hijacking_script_mixing",

  // HTTP and validation flags
  HTTP_VALIDATION_FAILED = "http_validation_failed",
  HTTP_VALIDATED = "http_validated",
  HTTP_ERROR = "http_error",
  HTTP_TIMEOUT = "http_timeout",

  // Content wrapping flags
  UNTRUSTED_WRAPPED = "untrusted_wrapped",
}
