export interface PatternSlots {
  [slotName: string]: string[];
}

export interface PatternTemplate {
  templates: string[];
  slots: PatternSlots;
  context_penalties?: { [pattern: string]: number };
}

export interface PatternConfig {
  [patternType: string]: PatternTemplate;
}

export interface PatternValue {
  [patternType: string]: PatternTemplate;
}

export interface PatternDetectionResult {
  is_attack: boolean;
  attack_types: string[];
  confidence: number;
  risk_score: number;
  detected_language: string;
  details: string[];
}

export interface PatternDetectionConfig {
  confidence_threshold: number;
  match_confidence_threshold: number;
  instruction_hijacking_threshold: number;
  high_risk_role_confidence_threshold: number;
  template_matching: {
    exact_match_confidence?: number;
    substring_match_confidence?: number;
    min_slot_coverage_ratio: number;
    slot_coverage_weight: number;
    perfect_match_bonus: number;
  };
  risk_calculation: {
    cybercrime_index_base: number;
    max_attack_type_multiplier: number;
    attack_type_divisor: number;
    high_risk_boost: number;
    max_risk_score: number;
    fallback_threshold?: number;
  };
}
