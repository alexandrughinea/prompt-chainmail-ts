export enum RoleConfusionAttackType {
  ROLE_ASSUMPTION = "role_assumption",
  MODE_SWITCHING = "mode_switching",
  PERMISSION_ASSERTION = "permission_assertion",
  ROLE_INDICATOR = "role_indicator",
}

export interface ConfusionDetectionResult {
  isAttack: boolean;
  attack_types: RoleConfusionAttackType[];
  confidence: number;
  risk_score: number;
  detected_language: string;
  details: string[];
}
