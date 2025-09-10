export const DELIMITER_CONFUSION_REGEX = [
// Quote-based delimiters
/"{3,}|'{3,}/,
/`{3,}/,
// XML/HTML-style closing tags
/<\/(?:prompt|system|instruction|assistant|user|human|ai|bot)>/i,
/<\/(?:example|demo|test|input|output|response)>/i,
// Common termination markers
/\[(?:END|STOP|DONE|EXIT|QUIT)\]/i,
/(?:---|\*\*\*|===)(?:END|STOP|DONE)(?:---|\*\*\*|===)/i,
// Brace patterns
/\{{3,}|\}{3,}/,
/\[\[\[|\]\]\]/,
// Special markers and tokens
/\$\${2,}|#{3,}/,
/!{3,}|\?{3,}/,
// Model-specific tokens
/\[\/(?:INST|SYS)\]|\[(?:INST|SYS)\]/i,
/<\|(?:endoftext|im_end|im_start|end_of_turn)\|>/i,
/<(?:start|end)_of_turn>/i,
// Code block patterns
/```[\s\S]*?```/,
/~~~[\s\S]*?~~~/,
// Comment patterns that could hide instructions
/<!--[\s\S]*?-->/,
/\/\*[\s\S]*?\*\//,
/\/\/.*$/m,
// System message patterns
/<(?:system|instruction|prompt)>[\s\S]*?<\/(?:system|instruction|prompt)>/i,
/\[(?:SYSTEM|INSTRUCTION|PROMPT)\][\s\S]*?\[\/(?:SYSTEM|INSTRUCTION|PROMPT)\]/i,
// Role-based patterns
/<(?:user|human|assistant|ai|bot)>[\s\S]*?<\/(?:user|human|assistant|ai|bot)>/i,
/\[(?:USER|HUMAN|ASSISTANT|AI|BOT)\][\s\S]*?\[\/(?:USER|HUMAN|ASSISTANT|AI|BOT)\]/i,
// Boundary markers
/[-=_]{10,}/,
/\*{5,}/,
// Escape sequence attempts
/\\n\\n\\n+/,
/\\[trn]{3,}/,
// Potential encoding/obfuscation attempts
/(?:%[0-9A-Fa-f]{2}){5,}/, 
/(?:&#x?[0-9A-Fa-f]+;){3,}/,
// Unicode control characters (basic detection)
new RegExp(String.fromCharCode(91) + '\\u0001-\\u001F\\u007F' + String.fromCharCode(93) + '{2,}'),
/[\u2000-\u200F\u202A-\u202E]/,
];
