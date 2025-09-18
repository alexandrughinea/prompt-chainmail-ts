export const SANITIZE_HTML_TAG_PATTERN = /<[^>]*>/;

export const SANITIZE_HTML_ENTITIES = {
  AMP: /&amp;/g,
  LT: /&lt;/g,
  GT: /&gt;/g,
  QUOT: /&quot;/g,
  APOS: /&#x27;/g,
} as const;

export const SANITIZE_CONTROL_CHAR_PATTERN = /[\x7F]/;
export const SANITIZE_CONTROL_CHAR_REPLACEMENT = "[CTRL_REDACTED]";
