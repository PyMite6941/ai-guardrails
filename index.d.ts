/**=============================================================================
 * @pymite6941/ai-guardrails — TypeScript definitions
 *=============================================================================*/

export interface GuardrailOptions {
  baseUrl?: string;
  timeout?: number;
  page?: string;
  agent?: string;
}

export interface ValidateResult {
  safe: boolean;
  reason: string;
  blockedBy: string | null;
  reported: boolean;
  censored: boolean;
  censorReason: string;
}

export interface AIGuardrailsOptions extends GuardrailOptions {}

export class AIGuardrails {
  constructor(options?: GuardrailOptions);
  validate(text: string, opts?: { kind?: "input" | "output"; page?: string; agent?: string }): Promise<ValidateResult>;
  validateInput(text: string, opts?: { page?: string; agent?: string }): Promise<ValidateResult>;
  validateOutput(text: string, opts?: { page?: string; agent?: string }): Promise<ValidateResult>;
}

export const DEFAULT_POLICY: {
  blocked_input_patterns: string[];
  blocked_input_keywords: string[];
  blocked_output_patterns: string[];
  blocked_output_keywords: string[];
  harmful_content_patterns: string[];
};
