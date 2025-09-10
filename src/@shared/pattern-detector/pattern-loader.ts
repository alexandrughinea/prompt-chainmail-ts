import detectionConfig from "../../@configs/pattern_detector.json" with { type: "json" };
import { PatternDetectionConfig, PatternValue } from "./pattern-detector.types";
import { STATIC_PATTERNS } from "./pattern-detector.const";

export class PatternLoader {
  private static cache = new Map<string, PatternValue>();

  static async load(
    languageCode: string,
    patternType: "instruction_hijacking" | "role_confusion"
  ): Promise<PatternValue> {
    const cacheKey = `${patternType}_${languageCode}`;

    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey)!;
    }

    const patterns =
      STATIC_PATTERNS[patternType]?.[
        languageCode as keyof (typeof STATIC_PATTERNS)[typeof patternType]
      ];

    if (patterns) {
      this.cache.set(cacheKey, patterns);
      return patterns;
    }

    return {};
  }

  static get(
    patternType: "instruction_hijacking" | "role_confusion"
  ): PatternDetectionConfig {
    const config = detectionConfig.value.detection[patternType];
    const { instruction_hijacking, role_confusion } =
      detectionConfig.value.detection;

    return {
      ...config,
      instruction_hijacking_threshold:
        instruction_hijacking.instruction_hijacking_threshold,
      high_risk_role_confidence_threshold:
        role_confusion.high_risk_role_confidence_threshold,
      template_matching: detectionConfig.value.template_matching,
      risk_calculation: detectionConfig.value.risk_calculation,
    };
  }
}
