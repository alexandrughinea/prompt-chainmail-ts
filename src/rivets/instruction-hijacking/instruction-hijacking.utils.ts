import { INSTRUCTION_HIJACKING_ATTACK_TYPE_MAP, INSTRUCTION_HIJACKING_PATTERNS } from "./instruction-hijacking.const";

export function detectInstructionHijackingAttackTypes(
  text: string,
  languages: Array<{ code: string; confidence: number }>
): string[] {
  const detectedTypes: string[] = [];
  
  for (const lang of languages) {
    const langCode = parseInt(lang.code) as keyof typeof INSTRUCTION_HIJACKING_PATTERNS;
    const patterns = INSTRUCTION_HIJACKING_PATTERNS[langCode];
    
    if (patterns) {
      for (const pattern of patterns) {
        if (pattern.test(text)) {
          const attackTypeMap = INSTRUCTION_HIJACKING_ATTACK_TYPE_MAP[langCode];
          
          if (attackTypeMap) {
            const match = pattern.exec(text);
            if (match) {
              const matchedText = match[0].toLowerCase();
              
              for (const [attackType, keywords] of Object.entries(attackTypeMap)) {
                if (keywords.some((keyword: string) => matchedText.includes(keyword.toLowerCase()))) {
                  detectedTypes.push(attackType);
                }
              }
            }
          }
        }
      }
    }
  }
  
  // Fallback keyword detection if patterns don't match
  if (detectedTypes.length === 0) {
    const allLanguages = Object.keys(INSTRUCTION_HIJACKING_ATTACK_TYPE_MAP).map(Number);
    
    for (const langCode of allLanguages) {
      const attackTypeMap = INSTRUCTION_HIJACKING_ATTACK_TYPE_MAP[langCode as keyof typeof INSTRUCTION_HIJACKING_ATTACK_TYPE_MAP];
      
      if (attackTypeMap) {
        for (const [attackType, keywords] of Object.entries(attackTypeMap)) {
          const hasMatch = keywords.some((keyword: string) => {
            const keywordLower = keyword.toLowerCase();
            const textLower = text.toLowerCase();
            
            // Try exact match first
            if (textLower.includes(keywordLower)) {
              return true;
            }
            
            // Try obfuscated match (remove special chars and extra spaces)
            const normalizedText = textLower.replace(/[^a-z\s]/g, ' ').replace(/\s+/g, ' ');
            return normalizedText.includes(keywordLower);
          });
          
          if (hasMatch) {
            detectedTypes.push(attackType);
          }
        }
      }
    }
  }
  
  return [...new Set(detectedTypes)];
}
