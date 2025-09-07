import { ChainmailContext } from "../types";
import { ThreatLevel } from "./rivets.types";

export function applyThreatPenalty(
  context: ChainmailContext,
  level: ThreatLevel
): void {
  context.confidence = Math.max(0, context.confidence - level);
}
