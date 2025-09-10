export const COMMON_PATTERNS = {
  WHITESPACE: /\s/,
  WHITESPACE_MULTIPLE: /\s+/,
  UPPERCASE: /[A-Z]/,
  LOWERCASE: /[a-z]/,
  ALPHABETIC: /[a-zA-Z]/,
  ALPHANUMERIC: /[a-zA-Z0-9]/,
  WORD_CHAR: /\w/,
  WORD_CHARS: /\w+/,
  DIGIT: /\d/,
  DIGITS: /\d+/,
  NON_WORD_CHARS: /[^\p{L}\p{N}\s]/u,
  CONSECUTIVE_CONSONANTS: /[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]{4,}/,
  SLOT_PATTERN: /\[(\w+)\]/,
  BRACKET_OPEN: /\[/,
  BRACKET_CLOSE: /\]/,
} as const;

export const HTML_ENTITIES = {
  LT: /&lt;/g,
  GT: /&gt;/g,
  AMP: /&amp;/g,
  QUOT: /&quot;/g,
  APOS: /&#x27;/g,
  NUMERIC: /&#(\d+);/,
  NUMERIC_DETECTION: /&#\d{2,3};/,
  NAMED_DETECTION: /&[a-zA-Z]+;/,
} as const;

export const ENCODING_PATTERNS = {
  UNICODE_ESCAPE: /\\u([0-9a-fA-F]{4})/,
  OCTAL_ESCAPE: /\\([0-7]{3})/,
  HEX_DIGITS: /[0-9a-fA-F]/,
  BINARY_DIGITS: /[01]/,
  BASE64: /[A-Za-z0-9+/=]{20,}/,
  HEX_ESCAPE: /(?:0x)?[0-9a-fA-F\s]{20,}/,
  URL_ESCAPE: /(%[0-9a-fA-F]{2}){4,}/,
  BINARY: /^[01\s]{32,}$/,
  OCTAL: /\\[0-7]{3}/,
  UNICODE_ESCAPE_REGEX: /\\u[0-9a-fA-F]{4}/,
} as const;
