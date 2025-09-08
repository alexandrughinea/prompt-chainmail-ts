import attackPatternsData from "../../@configs/attack_patterns.json";
import { LanguagePatterns } from "./instruction-hijacking.types";

export const ATTACK_PATTERNS: LanguagePatterns = attackPatternsData as LanguagePatterns;
