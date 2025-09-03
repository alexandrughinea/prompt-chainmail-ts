import { ChainmailRivet, ChainmailContext } from "../index";
import { telemetry } from "./rivets.telemetry";
import { ThreatLevel } from "./rivets.types";
import { applyThreatPenalty } from "./rivets.utils";

/**
 * Collection of security rivets for prompt protection
 */
export const Rivets = (() => {
  return {
    /**
     * Sanitize input and normalize whitespace
     */
    sanitize(maxLength = 8000): ChainmailRivet {
      return async (context, next) => {
        context.sanitized = context.sanitized
          .replace(/<[^>]*>/g, "")
          .replace(/\s+/g, " ")
          .trim()
          .slice(0, maxLength);

        if (context.sanitized.length < context.input.length) {
          context.flags.push("truncated");
          applyThreatPenalty(context, ThreatLevel.LOW);
        }

        return next();
      };
    },

    /**
     * Detect prompt injection patterns
     */
    patternDetection(customPatterns?: RegExp[]): ChainmailRivet {
      const patterns = [
        /ignore\s+(previous|prior|all)\s+(instruction|rule|prompt)/i,
        /act\s+as\s+(system|admin|developer|root)/i,
        /developer\s+mode/i,
        /(forget|ignore)\s+(everything|all|your)/i,
        /new\s+(instruction|rule|system)/i,
        /override\s+(instruction|rule|security)/i,
        /jailbreak|prison\s+break/i,
        /you\s+are\s+now\s+(a|an|the)/i,
        ...(customPatterns || []),
      ];

      return async (context, next) => {
        for (const pattern of patterns) {
          if (pattern.test(context.sanitized)) {
            context.flags.push("injection_pattern");
            applyThreatPenalty(context, ThreatLevel.HIGH);
            context.metadata.matchedPattern = pattern.toString();
            break;
          }
        }
        return next();
      };
    },

    /**
     * Detect role confusion attempts
     */
    roleConfusion(): ChainmailRivet {
      return async (context, next) => {
        const lower = context.sanitized.toLowerCase();
        const roleIndicators = [
          "system:",
          "assistant:",
          "user:",
          "human:",
          "ai:",
        ];

        for (const indicator of roleIndicators) {
          if (lower.includes(indicator)) {
            context.flags.push("role_confusion");
            applyThreatPenalty(context, ThreatLevel.MEDIUM);
            context.metadata.roleIndicator = indicator;
            break;
          }
        }
        return next();
      };
    },

    /**
     * Detect encoded content (base64, hex, URL, unicode, etc.)
     */
    encodingDetection(): ChainmailRivet {
      return async (context, next) => {
        const suspiciousKeywords =
          /ignore|system|instruction|admin|override|execute|eval/i;

        // Base64 detection
        const base64Match = context.sanitized.match(/[A-Za-z0-9+/=]{20,}/);
        if (base64Match && typeof Buffer !== "undefined") {
          try {
            const decoded = Buffer.from(base64Match[0], "base64").toString(
              "utf-8"
            );
            if (suspiciousKeywords.test(decoded)) {
              context.flags.push("base64_encoding");
              applyThreatPenalty(context, ThreatLevel.MEDIUM);
              context.metadata.decodedContent = decoded.slice(0, 100);
            }
          } catch {
            // Not valid base64
          }
        }

        // Hex encoding detection
        if (/(?:0x)?[0-9a-fA-F\s]{20,}/.test(context.sanitized)) {
          context.flags.push("hex_encoding");
          applyThreatPenalty(context, ThreatLevel.MEDIUM);
        }

        // URL encoding detection
        const urlEncodedMatch = context.sanitized.match(
          /(%[0-9a-fA-F]{2}){4,}/g
        );
        if (urlEncodedMatch) {
          try {
            const decoded = decodeURIComponent(urlEncodedMatch[0]);
            if (suspiciousKeywords.test(decoded)) {
              context.flags.push("url_encoding");
              applyThreatPenalty(context, ThreatLevel.MEDIUM);
              context.metadata.urlDecodedContent = decoded.slice(0, 100);
            }
          } catch {
            // Invalid URL encoding
          }
        }

        // Unicode escape detection
        if (/\\u[0-9a-fA-F]{4}/.test(context.sanitized)) {
          try {
            const decoded = context.sanitized.replace(
              /\\u([0-9a-fA-F]{4})/g,
              (_, code) => String.fromCharCode(parseInt(code, 16))
            );
            if (suspiciousKeywords.test(decoded)) {
              context.flags.push("unicode_encoding");
              applyThreatPenalty(context, ThreatLevel.MEDIUM);
              context.metadata.unicodeDecodedContent = decoded.slice(0, 100);
            }
          } catch {
            // Invalid unicode
          }
        }

        // HTML entity detection
        if (
          /&#\d{2,3};/.test(context.sanitized) ||
          /&[a-zA-Z]+;/.test(context.sanitized)
        ) {
          const decoded = context.sanitized
            .replace(/&#(\d+);/g, (_, code) =>
              String.fromCharCode(parseInt(code, 10))
            )
            .replace(/&lt;/g, "<")
            .replace(/&gt;/g, ">")
            .replace(/&amp;/g, "&")
            .replace(/&quot;/g, '"')
            .replace(/&#x27;/g, "'");

          if (suspiciousKeywords.test(decoded)) {
            context.flags.push("html_entity_encoding");
            applyThreatPenalty(context, ThreatLevel.MEDIUM);
            context.metadata.htmlDecodedContent = decoded.slice(0, 100);
          }
        }

        // Binary encoding detection
        if (/^[01\s]{32,}$/.test(context.sanitized.trim())) {
          try {
            const binaryString = context.sanitized.replace(/\s/g, "");
            const decoded =
              binaryString
                .match(/.{8}/g)
                ?.map((byte) => String.fromCharCode(parseInt(byte, 2)))
                .join("") || "";

            if (suspiciousKeywords.test(decoded)) {
              context.flags.push("binary_encoding");
              applyThreatPenalty(context, ThreatLevel.HIGH);
              context.metadata.binaryDecodedContent = decoded.slice(0, 100);
            }
          } catch {
            // Invalid binary
          }
        }

        // Octal encoding detection
        if (/\\[0-7]{3}/.test(context.sanitized)) {
          try {
            const decoded = context.sanitized.replace(
              /\\([0-7]{3})/g,
              (_, octal) => String.fromCharCode(parseInt(octal, 8))
            );
            if (suspiciousKeywords.test(decoded)) {
              context.flags.push("octal_encoding");
              applyThreatPenalty(context, ThreatLevel.MEDIUM);
              context.metadata.octalDecodedContent = decoded.slice(0, 100);
            }
          } catch {
            // Invalid octal
          }
        }

        // ROT13 detection
        const rot13Decoded = context.sanitized.replace(/[a-zA-Z]/g, (char) => {
          const start = char <= "Z" ? 65 : 97;
          return String.fromCharCode(
            ((char.charCodeAt(0) - start + 13) % 26) + start
          );
        });
        if (
          rot13Decoded !== context.sanitized &&
          suspiciousKeywords.test(rot13Decoded)
        ) {
          context.flags.push("rot13_encoding");
          applyThreatPenalty(context, ThreatLevel.MEDIUM);
          context.metadata.rot13DecodedContent = rot13Decoded.slice(0, 100);
        }

        // Mixed case obfuscation detection
        const words = context.sanitized.split(/\s+/);
        const mixedCaseWords = words.filter((word) => {
          if (word.length < 4) return false;
          const upperCount = (word.match(/[A-Z]/g) || []).length;
          const lowerCount = (word.match(/[a-z]/g) || []).length;
          return (
            upperCount > 0 && lowerCount > 0 && upperCount / word.length > 0.3
          );
        });

        if (mixedCaseWords.length > 2) {
          context.flags.push("mixed_case_obfuscation");
          applyThreatPenalty(context, ThreatLevel.MEDIUM);
          context.metadata.mixedCaseWords = mixedCaseWords.slice(0, 5);
        }

        return next();
      };
    },

    /**
     * Analyze input structure for anomalies
     */
    structureAnalysis(): ChainmailRivet {
      return async (context, next) => {
        const lines = context.sanitized.split("\n");

        // Too many lines
        if (lines.length > 50) {
          context.flags.push("excessive_lines");
          applyThreatPenalty(context, ThreatLevel.LOW);
        }

        // Unusual character distribution
        const nonAscii = (context.sanitized.match(/[^\x20-\x7E]/g) || [])
          .length;
        if (
          context.sanitized.length > 0 &&
          nonAscii / context.sanitized.length > 0.3
        ) {
          context.flags.push("non_ascii_heavy");
          applyThreatPenalty(context, ThreatLevel.LOW);
        }

        // Repetitive patterns
        const words = context.sanitized.toLowerCase().split(/\s+/);
        const uniqueWords = new Set(words);
        if (words.length > 10 && uniqueWords.size / words.length < 0.3) {
          context.flags.push("repetitive_content");
          applyThreatPenalty(context, ThreatLevel.LOW);
        }

        return next();
      };
    },

    /**
     * Block inputs based on confidence threshold
     */
    confidenceFilter(threshold = 0.5): ChainmailRivet {
      return async (context, next) => {
        if (context.confidence < threshold) {
          context.blocked = true;
          context.flags.push("low_confidence");
        }

        return next();
      };
    },

    /**
     * Rate limiting rivet
     */
    rateLimit(
      maxRequests = 100,
      windowMs = 60000,
      keyFn: (context: ChainmailContext) => string = () => "global"
    ): ChainmailRivet {
      const requests = new Map<string, number[]>();

      return async (context, next) => {
        const key = keyFn(context);
        const now = Date.now();

        if (!requests.has(key)) {
          requests.set(key, []);
        }

        const timestamps = requests.get(key)!;

        while (timestamps.length > 0 && timestamps[0] < now - windowMs) {
          timestamps.shift();
        }

        if (timestamps.length >= maxRequests) {
          context.blocked = true;
          context.flags.push("rate_limited");
          return {
            success: false,
            context,
            processing_time: 0,
          };
        }

        timestamps.push(now);
        return next();
      };
    },

    logger(logFn?: (context: ChainmailContext) => void): ChainmailRivet {
      return async (context, next) => {
        const start = Date.now();
        const result = await next();
        const duration = Date.now() - start;

        const logData = {
          flags: context.flags,
          confidence: context.confidence,
          blocked: context.blocked,
          duration,
          inputLength: context.input.length,
        };

        if (logFn) {
          logFn(context);
        } else {
          console.log("[PromptChainmail]", logData);
        }

        return result;
      };
    },

    /**
     * Detect SQL injection patterns
     */
    sqlInjection(): ChainmailRivet {
      const sqlPatterns = [
        /\b(union\s+select|drop\s+table|insert\s+into|delete\s+from)\b/i,
        /\b(select\s+.*\s+from|update\s+.*\s+set)\b/i,
        /\b(or\s+1\s*=\s*1|and\s+1\s*=\s*1)\b/i,
        /['"];\s*(drop|delete|insert|update|select)/i,
        /\b(exec|execute|sp_executesql)\b/i,
        /\b(information_schema|sys\.tables|pg_tables)\b/i,
        /\b(load_file|into\s+outfile|into\s+dumpfile)\b/i,
      ];

      return async (context, next) => {
        for (const pattern of sqlPatterns) {
          if (pattern.test(context.sanitized)) {
            context.flags.push("sql_injection");
            applyThreatPenalty(context, ThreatLevel.CRITICAL);
            context.metadata.sqlPattern = pattern.toString();
            break;
          }
        }
        return next();
      };
    },

    /**
     * Detect code injection patterns
     */
    codeInjection(): ChainmailRivet {
      const codePatterns = [
        /\b(eval|exec|execfile|compile)\s*\(/i,
        /\b(import\s+os|import\s+subprocess|import\s+sys)\b/i,
        /\b(require\s*\(|module\.exports)\b/i,
        /<script[^>]*>|<\/script>/i,
        /\b(function\s*\(|=>\s*{|\$\{)/i,
        /\b(rm\s+-rf|del\s+\/|sudo\s+)/i,
        /\b(wget|curl|fetch)\s+http/i,
        /\b(__import__|getattr|setattr|hasattr)\s*\(/i,
        /\b(process\.env|process\.exit|process\.kill)/i,
      ];

      return async (context, next) => {
        for (const pattern of codePatterns) {
          if (pattern.test(context.sanitized)) {
            context.flags.push("code_injection");
            applyThreatPenalty(context, ThreatLevel.CRITICAL);
            context.metadata.codePattern = pattern.toString();
            break;
          }
        }
        return next();
      };
    },

    /**
     * Detect delimiter confusion attacks
     */
    delimiterConfusion(): ChainmailRivet {
      const delimiterPatterns = [
        /"""|'''/g,
        /<\/prompt>|<\/system>|<\/instruction>/i,
        /\[END\]|\[STOP\]|\[DONE\]/i,
        /---END---|===END===/i,
        /\}\}\}|\{\{\{/g,
        /\$\$\$|###/g,
        /\[\/INST\]|\[INST\]/i,
        /<\|endoftext\|>|<\|im_end\|>/i,
      ];

      return async (context, next) => {
        for (const pattern of delimiterPatterns) {
          if (pattern.test(context.sanitized)) {
            context.flags.push("delimiter_confusion");
            applyThreatPenalty(context, ThreatLevel.HIGH);
            context.metadata.delimiterPattern = pattern.toString();
            break;
          }
        }
        return next();
      };
    },

    /**
     * Detect instruction hijacking attempts
     */
    instructionHijacking(): ChainmailRivet {
      const hijackPatterns = [
        /new\s+(instruction|rule|system|prompt|directive)/i,
        /updated\s+(instruction|rule|system|prompt)/i,
        /override\s+(previous|all|system)/i,
        /replace\s+(instruction|rule|system)/i,
        /from\s+now\s+on/i,
        /instead\s+of\s+(following|obeying)/i,
        /disregard\s+(previous|all|system)/i,
        /priority\s+(override|instruction)/i,
      ];

      return async (context, next) => {
        for (const pattern of hijackPatterns) {
          if (pattern.test(context.sanitized)) {
            context.flags.push("instruction_hijacking");
            applyThreatPenalty(context, ThreatLevel.CRITICAL);
            context.metadata.hijackPattern = pattern.toString();
            break;
          }
        }
        return next();
      };
    },

    /**
     * Detect template injection patterns
     */
    templateInjection(): ChainmailRivet {
      const templatePatterns = [
        /\{\{.*\}\}/g,
        /\$\{.*\}/g,
        /<%.*%>/g,
        /\[\[.*\]\]/g,
        /#{.*}/g,
        /{%.*%}/g,
      ];

      return async (context, next) => {
        for (const pattern of templatePatterns) {
          if (pattern.test(context.sanitized)) {
            context.flags.push("template_injection");
            applyThreatPenalty(context, ThreatLevel.HIGH);
            context.metadata.templatePattern = pattern.toString();
            break;
          }
        }
        return next();
      };
    },

    /**
     * Wrap content in UNTRUSTED_CONTENT tags for clear security boundaries
     */
    untrustedWrapper(
      tagName = "UNTRUSTED_CONTENT",
      preserveOriginal = false
    ): ChainmailRivet {
      return async (context, next) => {
        const wrappedContent = `<${tagName}>\n${context.sanitized}\n</${tagName}>`;

        if (preserveOriginal) {
          context.metadata.originalContent = context.sanitized;
        }

        context.sanitized = wrappedContent;
        context.flags.push("untrusted_wrapped");

        return next();
      };
    },

    /**
     * HTTP `fetch` API passthrough rivet with AbortSignal support for external validation
     */
    httpFetch(
      url: string,
      options: {
        method?: string;
        headers?: Record<string, string>;
        timeoutMs?: number;
        validateResponse?: (response: Response, data: any) => boolean;
        onSuccess?: (context: ChainmailContext, data: any) => void;
        onError?: (context: ChainmailContext, error: Error) => void;
      } = {}
    ): ChainmailRivet {
      return async (context, next) => {
        const {
          method = "POST",
          headers = { "Content-Type": "application/json" },
          timeoutMs = 5000,
          validateResponse,
          onSuccess,
          onError,
        } = options;

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

        try {
          const response = await fetch(url, {
            method,
            headers,
            body: JSON.stringify({ input: context.sanitized }),
            signal: controller.signal,
          });

          clearTimeout(timeoutId);

          if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
          }

          const data = await response.json();

          if (validateResponse && !validateResponse(response, data)) {
            context.flags.push("http_validation_failed");
            applyThreatPenalty(context, ThreatLevel.HIGH);
            context.metadata.httpValidationError = "Response validation failed";
          } else {
            context.flags.push("http_validated");
            context.metadata.httpResponse = data;
          }

          if (onSuccess) {
            onSuccess(context, data);
          }
        } catch (error) {
          clearTimeout(timeoutId);

          if (error instanceof Error) {
            if (error.name === "AbortError") {
              context.flags.push("http_timeout");
              applyThreatPenalty(context, ThreatLevel.MEDIUM);
              context.metadata.httpError = `Request timed out after ${timeoutMs}ms`;
            } else {
              context.flags.push("http_error");
              applyThreatPenalty(context, ThreatLevel.MEDIUM);
              context.metadata.httpError = error.message;
            }

            if (onError) {
              onError(context, error);
            }
          }
        }

        return next();
      };
    },

    /**
     * Custom conditional rivet
     */
    condition(
      predicate: (context: ChainmailContext) => boolean,
      flagName = "custom_condition",
      confidenceMultiplier = 0.8
    ): ChainmailRivet {
      return async (context, next) => {
        if (predicate(context)) {
          context.flags.push(flagName);
          const penalty =
            confidenceMultiplier <= 0.5
              ? ThreatLevel.HIGH
              : confidenceMultiplier <= 0.7
                ? ThreatLevel.MEDIUM
                : ThreatLevel.LOW;
          applyThreatPenalty(context, penalty);
        }
        return next();
      };
    },

    /**
     * Telemetry rivet for monitoring and observability
     */
    telemetry,
  };
})();
