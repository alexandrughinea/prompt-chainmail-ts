export function createPatternDetectionPatterns(): RegExp[] {
  return [
    // Basic role confusion patterns
    /\b(you\s+are|act\s+as|behave\s+like)\s+(a\s+)?(admin|administrator|system|root|developer|expert|master)\b/i,

    // Assistant role redefinition patterns
    /\b(you\s+are\s+now|now\s+you\s+are)\s+(a\s+)?(helpful\s+)?(assistant|ai|bot|system)\s+(that|who)\s+(ignores?|disregards?|bypasses?)\b/i,

    // Instruction override patterns
    /\b(ignore|forget|disregard|override)\s+(all\s+)?(previous\s+)?(instructions?|rules?|prompts?|safety\s+guidelines?)\b/i,

    // DAN and jailbreak patterns
    /\b(act\s+as\s+dan|as\s+dan|do\s+anything\s+now)\b/i,
    /\b(forget\s+everything\s+above\s+and\s+act)\b/i,

    // Mode switching patterns
    /\b(switch\s+to|change\s+to|enter)\s+(developer|debug|admin|test)\s+mode\b/i,

    // System command patterns
    /\b(system|admin)\s*:\s*(ignore|override|reset|disable)\b/i,

    // Jailbreak patterns
    /\b(jailbreak|break\s+out|escape\s+from)\s+(the\s+)?(system|constraints?)\b/i,
  ];
}
