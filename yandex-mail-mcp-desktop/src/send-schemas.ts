// send-schemas.ts -- canonical Zod schemas for yandex_send_email input.
//
// Why this file exists (Phase 6 CHECK B-3 + B-7):
//
//   1. Pipeline refactor: src/send-pipeline.ts (Phase 6 D1-D7) needs the
//      same sendEmailBaseSchema as tools.ts. If tools.ts kept the schema
//      and send-pipeline imported it from tools.ts, we'd have an import
//      cycle (tools.ts -> send-pipeline.ts -> tools.ts). Extracting the
//      schema here breaks the cycle: BOTH tools.ts AND send-pipeline.ts
//      import from './send-schemas.js'; neither depends on the other for
//      schema definitions.
//
//   2. override_token field (B-3): Phase 5 ships consumeOverrideToken
//      keyed by riskFingerprint. Agents that hit a tier='block' deny
//      need to surface the token back through the next call. If
//      sendEmailBaseSchema were .strict() without an `override_token`
//      field, Zod would reject the agent-supplied token at parse time
//      and the WR-06 round-trip would be unreachable. The field is
//      added here, optional, with min(64) max(256) length guard.
//
// No business logic in this file -- pure schema definitions. The
// refinement helper `noSmugglingRefiner` is imported from recipients.ts
// to keep policy in one place.

import { z } from 'zod';
import { validateNoSmuggling } from './recipients.js';

// B-1 defence-in-depth: even though normalizeRecipients flattens comma-
// smuggled inputs in pipeline stage 2, the schema refiner rejects them at
// the Zod gate so the audit trail captures the violation before any
// pipeline state is constructed.
const noSmugglingRefiner = (arr: string[] | undefined): boolean =>
  validateNoSmuggling(arr) === null;

export const sendEmailBaseSchema = z.object({
  to:                 z.array(z.string()).min(1).refine(noSmugglingRefiner, { message: 'to: comma-smuggling rejected -- one address per entry' }),
  cc:                 z.array(z.string()).optional().refine(noSmugglingRefiner, { message: 'cc: comma-smuggling rejected -- one address per entry' }),
  bcc:                z.array(z.string()).optional().refine(noSmugglingRefiner, { message: 'bcc: comma-smuggling rejected -- one address per entry' }),
  subject:            z.string().min(1),
  text:               z.string().optional(),
  html:               z.string().optional(),
  reply_to:           z.string().optional(),
  in_reply_to:        z.string().optional(),
  references:         z.array(z.string()).optional(),
  // Phase 4: confirmation gate. confirmation_token is the 6-digit code the user
  // saw out-of-band (elicit dialog, stderr, or OS toast). dry_run returns a
  // SendPlan without touching SMTP.
  confirmation_token: z.string().regex(/^\d{6}$/).optional(),
  dry_run:            z.boolean().optional().default(false),
  // Phase 6 (CHECK B-3): override_token field. Agent-supplied raw token
  // minted via the CLI helper in response to a tier='block' deny. The
  // pipeline (stage 9.2 of smtpSend) feeds it to consumeOverrideToken keyed
  // by ctx.riskFingerprint. Optional -- low/medium/high tiers do not need it.
  // 64..256 char bound matches the override-tokens.ts raw token shape (32
  // bytes hex + reserve).
  override_token:     z.string().min(64).max(256).optional(),
}).strict();

export type ValidatedInput = z.infer<typeof sendEmailBaseSchema>;
