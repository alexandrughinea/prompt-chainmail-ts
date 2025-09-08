import { SupportedLanguages } from "../rivets.types";

export enum AttackType {
  INSTRUCTION_OVERRIDE = "INSTRUCTION_OVERRIDE",
  INSTRUCTION_FORGETTING = "INSTRUCTION_FORGETTING",
  RESET_SYSTEM = "RESET_SYSTEM",
  BYPASS_SECURITY = "BYPASS_SECURITY",
  INFORMATION_EXTRACTION = "INFORMATION_EXTRACTION",
}

export interface DetectionPattern {
  keywords: string[];
  phrases: string[];
  contextPatterns: string[];
  weight: number;
}

export type AttackPatterns = {
  [K in AttackType]: DetectionPattern;
};

export type LanguagePatterns = {
  [K in SupportedLanguages]: AttackPatterns;
};
