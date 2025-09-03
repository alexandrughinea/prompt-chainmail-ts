import { Rivets } from "./rivets/index";


/**
 * Context object passed through the rivet chain during input processing.
 * Contains the current state of input analysis and security assessment.
 *
 * @public
 * @example Processing Context
 * ```typescript
 * const rivet: ChainmailRivet = async (context, next) => {
 *   // Check confidence level
 *   if (context.confidence < 0.5) {
 *     context.blocked = true;
 *     context.flags.push('low_confidence');
 *     context.metadata.reason = 'Confidence below threshold';
 *   }
 *   return next();
 * };
 * ```
 */
export interface ChainmailContext {
  /** Original input text before any processing */
  readonly input: string;
  /** Sanitized/processed text after rivet processing */
  sanitized: string;
  /** Array of security flags raised during processing */
  flags: string[];
  /**
   * Confidence score between 0-1, where:
   * - 1.0 = Completely safe
   * - 0.5 = Moderate risk
   * - 0.0 = High risk/malicious
   */
  confidence: number;
  /** Custom metadata for extensions and debugging */
  metadata: Record<string, unknown>;
  /** Whether the input should be blocked based on security analysis */
  blocked: boolean;
  /** Processing start timestamp */
  readonly start_time: number;
  /** Unique identifier for this processing session */
  readonly session_id: string;
}

/**
 * Result object returned after processing input through the chainmail.
 * Contains success status, processing context, and any errors encountered.
 *
 * @public
 * @example Handling Results
 * ```typescript
 * const result = await chainmail.protect(userInput);
 *
 * if (result.success) {
 *   // Safe to process
 *   await processInput(result.context.sanitized);
 * } else {
 *   // Handle security violation
 *   logger.warn('Security violation', {
 *     flags: result.context.flags,
 *     confidence: result.context.confidence
 *   });
 * }
 * ```
 */
export interface ChainmailResult {
  /** Whether the input passed all security checks */
  success: boolean;
  /** Processing context containing analysis results */
  context: ChainmailContext;
  /** Error message if processing failed */
  error?: string;
  /** Processing duration in milliseconds */
  processing_time: number;
  /** Memory usage during processing in bytes */
  memory_usage?: number;
}

/**
 * A rivet function that processes input context and can modify it.
 * Rivets are chained together to form a complete security pipeline.
 *
 * @param context - The current processing context
 * @param next - Function to call the next rivet in the chain
 * @returns Promise resolving to the processing result
 *
 * @public
 * @example Custom Rivet
 * ```typescript
 * const customRivet: ChainmailRivet = async (context, next) => {
 *   // Pre-processing logic
 *   if (context.sanitized.includes('forbidden')) {
 *     context.flags.push('forbidden_content');
 *     context.confidence *= 0.5;
 *   }
 *
 *   // Continue to next rivet
 *   const result = await next();
 *
 *   // Post-processing logic
 *   if (!result.success) {
 *     context.metadata.failureReason = 'Custom rivet detected issue';
 *   }
 *
 *   return result;
 * };
 * ```
 */
export type ChainmailRivet = (
  context: ChainmailContext,
  next: () => Promise<ChainmailResult>
) => Promise<ChainmailResult>;


/**
 * Core chainmail class for forging security rivets
 *
 * @example
 * ```typescript
 * const chainmail = new PromptChainmail()
 *   .forge(Rivets.sanitize())
 *   .forge(Rivets.patternDetection())
 *   .forge(Rivets.confidenceFilter(0.7));
 *
 * const result = await chainmail.protect(userInput);
 * ```
 */
export class PromptChainmail {
  private rivets: ChainmailRivet[] = [];

  /**
   * Forge a new rivet into the chainmail
   */
  forge(rivet: ChainmailRivet): this {
    this.rivets.push(rivet);
    return this;
  }

  /**
   * Protect input by running it through all forged rivets
   */
  async protect(input: string): Promise<ChainmailResult> {
    const startTime = Date.now();
    const sessionId = `chainmail_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    const context: ChainmailContext = {
      input,
      sanitized: input,
      flags: [],
      confidence: 1.0,
      metadata: {},
      blocked: false,
      start_time: startTime,
      session_id: sessionId,
    };

    let index = 0;

    const next = async (): Promise<ChainmailResult> => {
      if (index >= this.rivets.length) {
        const processingTime = Date.now() - startTime;
        return {
          success: !context.blocked,
          context,
          processing_time: processingTime,
        };
      }

      const rivet = this.rivets[index++];
      return rivet(context, next);
    };

    try {
      return await next();
    } catch (error) {
      const processingTime = Date.now() - startTime;
      return {
        success: false,
        context,
        error: error instanceof Error ? error.message : "Unknown error",
        processing_time: processingTime,
      };
    }
  }

  /**
   * Create a new chainmail with the same rivets
   */
  clone(): PromptChainmail {
    const chainmail = new PromptChainmail();
    chainmail.rivets = [...this.rivets];
    return chainmail;
  }

  /**
   * Get the number of rivets in the chainmail
   */
  get length(): number {
    return this.rivets.length;
  }
}

/**
 * Pre-forged chainmail configurations
 */
export const Chainmails: Record<string, () => PromptChainmail> = {
  /**
   * Basic protection chainmail
   */
  basic(): PromptChainmail {
    return new PromptChainmail()
      .forge(Rivets.sanitize())
      .forge(Rivets.patternDetection())
      .forge(Rivets.roleConfusion())
      .forge(Rivets.delimiterConfusion())
      .forge(Rivets.confidenceFilter(0.6))
  },

  /**
   * Advanced protection chainmail with encoding detection
   */
  advanced(): PromptChainmail {
    return new PromptChainmail()
      .forge(Rivets.sanitize())
      .forge(Rivets.patternDetection())
      .forge(Rivets.roleConfusion())
      .forge(Rivets.delimiterConfusion())
      .forge(Rivets.instructionHijacking())
      .forge(Rivets.codeInjection())
      .forge(Rivets.sqlInjection())
      .forge(Rivets.templateInjection())
      .forge(Rivets.encodingDetection())
      .forge(Rivets.structureAnalysis())
      .forge(Rivets.confidenceFilter(0.5))
      .forge(Rivets.rateLimit());
  },

  /**
   * Development chainmail with comprehensive logging
   */
  development(): PromptChainmail {
    return Chainmails.advanced().forge(Rivets.logger());
  },

  /**
   * Strict chainmail for high-security environments
   */
  strict(): PromptChainmail {
    return new PromptChainmail()
      .forge(Rivets.sanitize(4000))
      .forge(Rivets.patternDetection())
      .forge(Rivets.roleConfusion())
      .forge(Rivets.delimiterConfusion())
      .forge(Rivets.instructionHijacking())
      .forge(Rivets.codeInjection())
      .forge(Rivets.sqlInjection())
      .forge(Rivets.templateInjection())
      .forge(Rivets.encodingDetection())
      .forge(Rivets.structureAnalysis())
      .forge(Rivets.confidenceFilter(0.8))
      .forge(Rivets.rateLimit(50, 60000));
  },
};

