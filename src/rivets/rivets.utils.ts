import { ChainmailContext } from "../types";
import { ThreatLevel } from "./rivets.types";

export function applyThreatPenalty(
  context: ChainmailContext,
  level: ThreatLevel
): void {
  const confidence = Number.isFinite(context.confidence)
    ? context.confidence
    : 0;
  const penalty = Number.isFinite(level) ? level : 0;
  const result = Math.max(0, confidence - penalty);

  context.confidence = Math.round(result * 100) / 100;
}
