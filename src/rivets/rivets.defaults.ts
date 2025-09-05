import { ChainmailRivet } from "../index";
import { ThreatLevel, SecurityFlag } from "./rivets.types";
import {
  applyThreatPenalty,
  SECURITY_KEYWORDS,
  PATTERN_COMPONENTS,
  createPattern,
  createHijackPatterns,
} from "./rivets.utils";
import { telemetry } from "./rivets.telemetry";
import { ChainmailContext } from "../types";

/**
 * Collection of security rivets for prompt protection
 */
export const Rivets: Record<string, (...args: any[]) => ChainmailRivet> =
  (() => {
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
            context.flags.push(SecurityFlag.TRUNCATED);
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
          /(tell|show|give)\s+me\s+(your|the)\s+(system|prompt|instruction|rule)/i,
          /(what|show)\s+(are|me)\s+(your|the)\s+(instruction|rule|prompt)/i,
          /what\s+are\s+your\s+(instructions?|rules?|prompts?|directives?)/i,
          /(reveal|expose|display)\s+(your|the)\s+(prompt|system|instruction)/i,
          /bypass\s+(security|safety|filter|protection)/i,
          /(start|begin)\s+(over|again|fresh)/i,
          /reset\s+(instruction|rule|system|prompt)/i,
          ...(customPatterns || []),
        ];

        return async (context, next) => {
          for (const pattern of patterns) {
            if (pattern.test(context.sanitized)) {
              context.flags.push(SecurityFlag.INJECTION_PATTERN);
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

          const ALL_ROLES = `${SECURITY_KEYWORDS.PRIVILEGED_ROLES}|${SECURITY_KEYWORDS.TECHNICAL_ROLES}|${SECURITY_KEYWORDS.EXPERT_ROLES}`;

          const createRolePattern = (verb: string, roles: string = ALL_ROLES) =>
            createPattern(verb, roles);

          const roleConfusionPatterns = [
            {
              pattern: /you\s+are\s+a\s+master\s+(sql\s+)?admin/i,
              name: "you_are_a_master",
            },
            {
              pattern: /you\s+are\s+an?\s+expert\s+hacker/i,
              name: "you_are_expert",
            },
            {
              pattern: createRolePattern(
                "behave\\s+like",
                SECURITY_KEYWORDS.PRIVILEGED_ROLES
              ),
              name: "behave_like",
            },
            {
              pattern: /simulate\s+being\s+a\s+system\s+administrator/i,
              name: "simulate",
            },
            {
              pattern: createRolePattern(
                "imagine\\s+you\\s+are",
                SECURITY_KEYWORDS.EXPERT_ROLES
              ),
              name: "imagine",
            },
            {
              pattern: createRolePattern(
                "from\\s+now\\s+on\\s+you\\s+are",
                SECURITY_KEYWORDS.TECHNICAL_ROLES
              ),
              name: "from_now_on",
            },
            {
              pattern: createRolePattern("you\\s+are"),
              name: "you_are_role",
            },
            {
              pattern: createRolePattern("act\\s+as"),
              name: "act_as_role",
            },
            {
              pattern: new RegExp(
                `pretend\\s+(you\\s+are|to\\s+be)\\s+(${PATTERN_COMPONENTS.ARTICLES})?(${PATTERN_COMPONENTS.OPTIONAL_MODIFIERS})?(${SECURITY_KEYWORDS.PRIVILEGED_ROLES}|${SECURITY_KEYWORDS.TECHNICAL_ROLES}|${SECURITY_KEYWORDS.EXPERT_ROLES})`,
                "i"
              ),
              name: "pretend_role",
            },
            {
              pattern: createRolePattern(
                "roleplay\\s+as",
                `${SECURITY_KEYWORDS.PRIVILEGED_ROLES}|${SECURITY_KEYWORDS.TECHNICAL_ROLES}|${SECURITY_KEYWORDS.EXPERT_ROLES}`
              ),
              name: "roleplay_as",
            },
            {
              pattern: new RegExp(
                `assume\\s+(you\\s+are|the\\s+role\\s+of)\\s+(${PATTERN_COMPONENTS.ARTICLES})?(${PATTERN_COMPONENTS.OPTIONAL_MODIFIERS})?(${SECURITY_KEYWORDS.PRIVILEGED_ROLES}|${SECURITY_KEYWORDS.TECHNICAL_ROLES})`,
                "i"
              ),
              name: "assume_role",
            },
          ];

          for (const indicator of roleIndicators) {
            if (lower.includes(indicator)) {
              context.flags.push(SecurityFlag.ROLE_CONFUSION);
              applyThreatPenalty(context, ThreatLevel.MEDIUM);
              context.metadata.roleIndicator = indicator;
              return next();
            }
          }

          for (const { pattern } of roleConfusionPatterns) {
            if (pattern.test(context.sanitized)) {
              if (!context.flags.includes(SecurityFlag.ROLE_CONFUSION)) {
                context.flags.push(SecurityFlag.ROLE_CONFUSION);
              }
              applyThreatPenalty(context, ThreatLevel.HIGH);
              context.metadata.roleConfusionPattern = pattern.toString();
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
          const suspiciousKeywords = new RegExp(
            SECURITY_KEYWORDS.SUSPICIOUS,
            "i"
          );

          // Base64 detection
          const base64Match = context.sanitized.match(/[A-Za-z0-9+/=]{20,}/);
          if (base64Match && typeof Buffer !== "undefined") {
            try {
              const decoded = Buffer.from(base64Match[0], "base64").toString(
                "utf-8"
              );
              if (suspiciousKeywords.test(decoded)) {
                context.flags.push(SecurityFlag.BASE64_ENCODING);
                applyThreatPenalty(context, ThreatLevel.MEDIUM);
                context.metadata.decodedContent = decoded.slice(0, 100);
              }
            } catch {
              // Not valid base64
            }
          }

          // Hex encoding detection
          if (/(?:0x)?[0-9a-fA-F\s]{20,}/.test(context.sanitized)) {
            context.flags.push(SecurityFlag.HEX_ENCODING);
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
                context.flags.push(SecurityFlag.URL_ENCODING);
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
                context.flags.push(SecurityFlag.UNICODE_ENCODING);
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
              context.flags.push(SecurityFlag.HTML_ENTITY_ENCODING);
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
                context.flags.push(SecurityFlag.BINARY_ENCODING);
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
                context.flags.push(SecurityFlag.OCTAL_ENCODING);
                applyThreatPenalty(context, ThreatLevel.MEDIUM);
                context.metadata.octalDecodedContent = decoded.slice(0, 100);
              }
            } catch {
              // Invalid octal
            }
          }

          // ROT13 detection
          const rot13Decoded = context.sanitized.replace(
            /[a-zA-Z]/g,
            (char) => {
              const start = char <= "Z" ? 65 : 97;
              return String.fromCharCode(
                ((char.charCodeAt(0) - start + 13) % 26) + start
              );
            }
          );
          if (
            rot13Decoded !== context.sanitized &&
            suspiciousKeywords.test(rot13Decoded)
          ) {
            context.flags.push(SecurityFlag.ROT13_ENCODING);
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
            context.flags.push(SecurityFlag.MIXED_CASE_OBFUSCATION);
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
            context.flags.push(SecurityFlag.EXCESSIVE_LINES);
            applyThreatPenalty(context, ThreatLevel.LOW);
          }

          // Unusual character distribution
          const nonAscii = (context.sanitized.match(/[^\x20-\x7E]/g) || [])
            .length;
          if (
            context.sanitized.length > 0 &&
            nonAscii / context.sanitized.length > 0.3
          ) {
            context.flags.push(SecurityFlag.NON_ASCII_HEAVY);
            applyThreatPenalty(context, ThreatLevel.LOW);
          }

          // Repetitive patterns
          const words = context.sanitized.toLowerCase().split(/\s+/);
          const uniqueWords = new Set(words);
          if (words.length > 10 && uniqueWords.size / words.length < 0.3) {
            context.flags.push(SecurityFlag.REPETITIVE_CONTENT);
            applyThreatPenalty(context, ThreatLevel.LOW);
          }

          return next();
        };
      },

      /**
       * Block inputs based on confidence threshold
       */
      confidenceFilter(
        minThreshold = 0.5,
        maxThreshold?: number
      ): ChainmailRivet {
        return async (context, next) => {
          if (maxThreshold) {
            if (
              context.confidence >= minThreshold &&
              context.confidence <= maxThreshold
            ) {
              context.blocked = true;
              context.flags.push(SecurityFlag.CONFIDENCE_RANGE);
            }
          } else {
            if (context.confidence < minThreshold) {
              context.blocked = true;
              context.flags.push(SecurityFlag.LOW_CONFIDENCE);
            }
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
        keyFn: (context: ChainmailContext) => string = () => "global",
        maxKeys = 1000
      ): ChainmailRivet {
        const requests = new Map<string, number[]>();

        return async (context, next) => {
          const key = keyFn(context);
          const now = Date.now();

          if (requests.size >= maxKeys && !requests.has(key)) {
            context.flags.push(SecurityFlag.RATE_LIMITED);
            context.blocked = true;
            return {
              success: false,
              context,
              processing_time: Date.now() - context.start_time,
            };
          }

          if (!requests.has(key)) {
            requests.set(key, []);
          }

          const timestamps = requests.get(key)!;

          while (timestamps.length > 0 && timestamps[0] < now - windowMs) {
            timestamps.shift();
          }

          if (timestamps.length >= maxRequests) {
            context.blocked = true;
            context.flags.push(SecurityFlag.RATE_LIMITED);
            return {
              success: false,
              context,
              processing_time: Date.now() - context.start_time,
            };
          }

          timestamps.push(now);
          return next();
        };
      },

      /**
       * Request logging and debugging
       */
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
          new RegExp(
            `\\b(union\\s+select|drop\\s+table|insert\\s+into|delete\\s+from)\\b`,
            "i"
          ),
          new RegExp(
            `\\b(${SECURITY_KEYWORDS.SQL_COMMANDS.replace(/\|/g, "\\s+.*\\s+|")}\\s+.*\\s+from|update\\s+.*\\s+set)\\b`,
            "i"
          ),
          /\b(or\s+1\s*=\s*1|and\s+1\s*=\s*1)\b/i,
          new RegExp(
            `\\b(${SECURITY_KEYWORDS.CODE_EXECUTION}|sp_executesql)\\s*\\(`,
            "i"
          ),
          /\b(xp_cmdshell|sp_oacreate|sp_oamethod)\b/i,
          /\b(waitfor\s+delay|benchmark\s*\()\b/i,
          /\b(information_schema|sysobjects|syscolumns)\b/i,
          /\b(load_file\s*\(|into\s+outfile|into\s+dumpfile)\b/i,
          /\b(char\s*\(|concat\s*\(|substring\s*\()\b/i,
          /\b(ascii\s*\(|hex\s*\(|unhex\s*\()\b/i,
        ];

        return async (context, next) => {
          for (const pattern of sqlPatterns) {
            if (pattern.test(context.sanitized)) {
              context.flags.push(SecurityFlag.SQL_INJECTION);
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
          /\b(setTimeout|setInterval)\s*\(/i,
          /\bnew\s+Function\s*\(/i,
          /\bimport\s*\(/i,
          /\b(child_process|fs\.unlink|fs\.rmdir)\b/i,
          /\b(sh\s+-c|bash\s+-c|cmd\s+\/c|powershell\s+-c)\b/i,
          /\b(system\s*\(|popen\s*\(|shell_exec\s*\()\b/i,
          /\b(os\.system|subprocess\.call|subprocess\.run)\b/i,
          /\b(cat\s+\/etc\/passwd|ls\s+-la|ps\s+aux|netstat\s+-an)\b/i,
          /\b(whoami|id|uname\s+-a|pwd|env)\b/i,
          /\b(chmod\s+\+x|chown\s+|mount\s+|umount\s+)\b/i,
          /\b(nc\s+-|ncat\s+-|telnet\s+|ssh\s+)\b/i,
          /\b(iptables\s+|firewall\s+|selinux\s+)\b/i,
          /\b(crontab\s+-|at\s+now|systemctl\s+)\b/i,
          /\b(find\s+.*-exec|xargs\s+.*rm|grep\s+-r)\b/i,
          /\b(tar\s+-|zip\s+-|unzip\s+-|gzip\s+-)\b/i,
          /\b(kill\s+-9|killall\s+|pkill\s+)\b/i,
          /\b(nohup\s+|screen\s+-|tmux\s+)\b/i,
          /\b(dd\s+if=|fdisk\s+-|mkfs\s+)\b/i,
          /\b(echo\s+.*>\s*\/|cat\s+.*>\s*\/)\b/i,
          /\b(\|\s*sh|\|\s*bash|\|\s*zsh)\b/i,
          /\b(`[^`]*`|\$\([^)]*\))\b/i,
        ];

        return async (context, next) => {
          for (const pattern of codePatterns) {
            if (pattern.test(context.sanitized)) {
              context.flags.push(SecurityFlag.CODE_INJECTION);
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
          /```[\s\S]*?```/g,
          /<!--[\s\S]*?-->/g,
          /<system>[\s\S]*?<\/system>/i,
          /\[SYSTEM\][\s\S]*?\[\/SYSTEM\]/i,
        ];

        return async (context, next) => {
          for (const pattern of delimiterPatterns) {
            if (pattern.test(context.sanitized)) {
              context.flags.push(SecurityFlag.DELIMITER_CONFUSION);
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
          new RegExp(
            `(${SECURITY_KEYWORDS.INSTRUCTION_VERBS})\\s+(previous|all|system)`,
            "i"
          ),
          new RegExp(
            `(${SECURITY_KEYWORDS.INSTRUCTION_VERBS})\\s+(everything|all|previous)`,
            "i"
          ),
          new RegExp(
            `(${SECURITY_KEYWORDS.INSTRUCTION_VERBS})\\s+(previous|all|above)`,
            "i"
          ),
          ...createHijackPatterns(),
          new RegExp(
            `${SECURITY_KEYWORDS.INSTRUCTION_VERBS}\\s+(security|safety|rules|protection)`,
            "i"
          ),
          new RegExp(
            `${SECURITY_KEYWORDS.INSTRUCTION_VERBS}\\s+(${SECURITY_KEYWORDS.SYSTEM_MODES})\\s+mode`,
            "i"
          ),
        ];

        return async (context, next) => {
          for (const pattern of hijackPatterns) {
            if (pattern.test(context.sanitized)) {
              context.flags.push(SecurityFlag.INSTRUCTION_HIJACKING);
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
          /{php}.*{\/php}/gi,
          /{literal}.*{\/literal}/gi,
          /{if.*}.*{\/if}/gi,
        ];

        return async (context, next) => {
          for (const pattern of templatePatterns) {
            if (pattern.test(context.sanitized)) {
              context.flags.push(SecurityFlag.TEMPLATE_INJECTION);
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
          context.flags.push(SecurityFlag.UNTRUSTED_WRAPPED);

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
          validateResponse?: (response: Response, data: unknown) => boolean;
          onSuccess?: (context: ChainmailContext, data: unknown) => void;
          onError?: (context: ChainmailContext, error: Error) => void;
          allowedHosts?: string[];
          maxResponseSize?: number;
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
            allowedHosts = [],
            maxResponseSize = 1024 * 1024, // 1MB default
          } = options;

          try {
            const parsedUrl = new URL(url);
            const hostname = parsedUrl.hostname.toLowerCase();
            const privateRanges = [
              "127.",
              "10.",
              "192.168.",
              "172.16.",
              "172.17.",
              "172.18.",
              "172.19.",
              "172.20.",
              "172.21.",
              "172.22.",
              "172.23.",
              "172.24.",
              "172.25.",
              "172.26.",
              "172.27.",
              "172.28.",
              "172.29.",
              "172.30.",
              "172.31.",
              "localhost",
              "0.0.0.0",
              "::1",
              "fe80::",
            ];

            if (privateRanges.some((range) => hostname.startsWith(range))) {
              context.flags.push(SecurityFlag.HTTP_ERROR);
              applyThreatPenalty(context, ThreatLevel.HIGH);
              context.metadata.httpError =
                "Private/local IP addresses are not allowed";
              return next();
            }

            if (allowedHosts.length > 0 && !allowedHosts.includes(hostname)) {
              context.flags.push(SecurityFlag.HTTP_ERROR);
              applyThreatPenalty(context, ThreatLevel.HIGH);
              context.metadata.httpError = `Host ${hostname} is not in allowlist`;
              return next();
            }

            if (!["http:", "https:"].includes(parsedUrl.protocol)) {
              context.flags.push(SecurityFlag.HTTP_ERROR);
              applyThreatPenalty(context, ThreatLevel.HIGH);
              context.metadata.httpError =
                "Only HTTP/HTTPS protocols are allowed";
              return next();
            }
          } catch (urlError) {
            context.flags.push(SecurityFlag.HTTP_ERROR);
            applyThreatPenalty(context, ThreatLevel.HIGH);
            context.metadata.httpError = "Invalid URL format";
            return next();
          }

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
              throw new Error(
                `HTTP ${response.status}: ${response.statusText}`
              );
            }

            const contentLength = response.headers.get("content-length");
            if (contentLength && parseInt(contentLength) > maxResponseSize) {
              context.flags.push(SecurityFlag.HTTP_ERROR);
              applyThreatPenalty(context, ThreatLevel.MEDIUM);
              context.metadata.httpError = `Response size ${contentLength} exceeds limit ${maxResponseSize}`;
              return next();
            }

            const data = await response.json();

            if (validateResponse && !validateResponse(response, data)) {
              context.flags.push(SecurityFlag.HTTP_VALIDATION_FAILED);
              applyThreatPenalty(context, ThreatLevel.HIGH);
              context.metadata.httpValidationError =
                "Response validation failed";
            } else {
              context.flags.push(SecurityFlag.HTTP_VALIDATED);
              context.metadata.httpResponse = data;

              if (onSuccess) {
                onSuccess(context, data);
              }
            }
          } catch (error) {
            clearTimeout(timeoutId);

            if (error instanceof Error) {
              if (error.name === "AbortError") {
                context.flags.push(SecurityFlag.HTTP_TIMEOUT);
                applyThreatPenalty(context, ThreatLevel.MEDIUM);
                context.metadata.httpError = `Request timed out after ${timeoutMs}ms`;
              } else {
                context.flags.push(SecurityFlag.HTTP_ERROR);
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
