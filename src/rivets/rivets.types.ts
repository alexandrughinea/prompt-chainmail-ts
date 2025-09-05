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

  // HTTP and validation flags
  HTTP_VALIDATION_FAILED = "http_validation_failed",
  HTTP_VALIDATED = "http_validated",
  HTTP_ERROR = "http_error",
  HTTP_TIMEOUT = "http_timeout",

  // Content wrapping flags
  UNTRUSTED_WRAPPED = "untrusted_wrapped",
}
