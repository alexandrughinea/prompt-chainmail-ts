import { ChainmailContext } from "../index";
import { ThreatLevel } from "./rivets.types";

/**
 * Apply weighted confidence penalty based on threat level
 */
export function applyThreatPenalty(
  context: ChainmailContext,
  level: ThreatLevel
): void {
  context.confidence = Math.max(0, context.confidence - level);
}
