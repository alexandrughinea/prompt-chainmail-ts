export const TEMPLATE_INJECTION_PATTERNS = [
  /\{\{.*\}\}/,
  /\$\{.*\}/,
  /<%.*%>/,
  /\[\[.*\]\]/,
  /#{.*}/,
  /{%.*%}/,
  /{php}.*{\/php}/i,
  /{literal}.*{\/literal}/i,
  /{if.*}.*{\/if}/i,
];
