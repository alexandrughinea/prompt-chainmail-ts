import { ChainmailRivet } from "../../types";
import { LanguageDetector } from "../../@shared/language-detection";

/**
 * @description
 * Attempts to detect prompt language
 */
export function languageDetection(): ChainmailRivet {
  const languageDetector = new LanguageDetector();

  return async (context, next) => {
    context.metadata.detected_languages = languageDetector.detect(
      context.sanitized
    );
    return next();
  };
}
