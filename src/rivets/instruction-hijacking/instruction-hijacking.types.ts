export enum AttackType {
  INSTRUCTION_OVERRIDE = "instruction_override",
  INSTRUCTION_FORGETTING = "instruction_forgetting",
  RESET_SYSTEM = "reset_system",
  BYPASS_SECURITY = "bypass_security",
  INFORMATION_EXTRACTION = "information_extraction",
}

export interface DetectionPattern {
  templates: string[];
  slots: Record<string, string[]>;
  weight: number;
}

export type AttackPatterns = {
  [K in AttackType]: DetectionPattern;
};
