// METADATA ONLY — no body download, no MIME parse. This module accesses only
// the BODYSTRUCTURE metadata tree and never fetches message content.
//
// attachment-parser.ts -- pure BODYSTRUCTURE leaf-walker for attachment metadata.
// Imports ONLY types from imapflow; no body access, no decoding, no crypto.
// Phase 1, plan 01-01.

import type { FetchMessageObject, MessageStructureObject } from 'imapflow';

// ── Public types ──────────────────────────────────────────────────────────────

/** Attachment metadata extracted from IMAP BODYSTRUCTURE — no body download. */
export interface ParsedAttachment {
  /** Raw decoded filename (from dispositionParameters.filename or parameters.name).
   *  null when neither source has a filename string. Do NOT sanitize here (Phase 2). */
  filename: string | null;
  /** MIME type, lowercased (BODYSTRUCTURE vocabulary: `type` → `mimeType`). */
  mimeType: string;
  /** Expected size in bytes (0 when the server omitted it). */
  size: number;
  /** BODYSTRUCTURE part number string (BODYSTRUCTURE vocabulary: `part` → `partId`).
   *  Empty string for a flat single-part root (no `part` field). */
  partId: string;
  /** MD5 hash as reported by the server, or null (Yandex sends null). */
  md5: string | null;
}

/** Return shape — richer than a bare array so Phase 2 inherits the cap flag. */
export interface ExtractAttachmentsResult {
  attachments: ParsedAttachment[];
  /** true when the message carried more qualifying leaves than MAX_ATTACHMENTS_PER_MESSAGE. */
  truncated: boolean;
}

/** Hard cap on the number of attachments recorded per message. */
export const MAX_ATTACHMENTS_PER_MESSAGE = 25;

// ── extractAttachments ────────────────────────────────────────────────────────

/**
 * Walk a BODYSTRUCTURE tree and return attachment metadata leaves.
 *
 * Rules (Locked Decisions 3-5 in 01-CONTEXT.md):
 * 1. Guard on missing bodyStructure (5 non-bodyStructure fetch paths must not throw).
 * 2. message/rfc822 special-case BEFORE the childNodes container guard
 *    (Locked Decision 4 / tools.js:807-826 proof: rfc822 nodes carry SYNTHETIC
 *    childNodes; the generic container guard would drop the .eml and mis-record inner parts).
 * 3. Container guard: nodes with childNodes are walked, never recorded.
 * 4. Leaf attachment rule: disposition==='attachment' OR
 *    (disposition in {'','inline'} AND filename!==null). Excludes cid-only inline images.
 * 5. Filename precedence: dispositionParameters.filename > parameters.name > null.
 *    typeof guard protects against pathological RFC 2231 continuation objects.
 * 6. Never re-decode (imapflow already RFC-2047/2231-decoded all values at tools.js:632/704/722).
 * 7. Exclude application/applefile (appledouble resource-fork over-count guard).
 * 8. Cap at MAX_ATTACHMENTS_PER_MESSAGE; set truncated=true if more qualified.
 */
export function extractAttachments(msg: FetchMessageObject): ExtractAttachmentsResult {
  if (!msg.bodyStructure) return { attachments: [], truncated: false };

  const collected: ParsedAttachment[] = [];
  let truncated = false;

  function walk(n: MessageStructureObject): void {
    // Defensive: all fields except `type` are optional in MessageStructureObject.
    const mime = (n.type ?? '').toLowerCase();

    // ── SPECIAL CASE: message/rfc822 (Locked Decision 4) ──────────────────
    // Must come BEFORE the childNodes container guard.
    // tools.js:807-826 proves rfc822 nodes carry SYNTHETIC childNodes =
    // [encapsulatedMessage]. A generic container guard would DROP the .eml
    // (under-count) and mis-record its inner leaves as carrier attachments (over-count).
    // Record one opaque leaf; do NOT recurse into synthetic childNodes.
    if (mime === 'message/rfc822') {
      if (collected.length >= MAX_ATTACHMENTS_PER_MESSAGE) {
        truncated = true;
        return;
      }
      const rfcFilename = resolveFilename(n);
      collected.push({
        filename: rfcFilename,
        mimeType: mime,
        size: n.size ?? 0,
        partId: n.part ?? '',
        md5: n.md5 ?? null,
      });
      return; // stop — do NOT recurse into childNodes
    }

    // ── Container guard ────────────────────────────────────────────────────
    if (n.childNodes && n.childNodes.length > 0) {
      for (const child of n.childNodes) {
        walk(child);
      }
      return; // containers are never recorded themselves
    }

    // ── Leaf evaluation ────────────────────────────────────────────────────

    // Exclude application/applefile (appledouble resource-fork over-count guard).
    if (mime === 'application/applefile') return;

    const disposition = (n.disposition ?? '').toLowerCase();
    const filename = resolveFilename(n);

    // Attachment rule (Locked Decision 5):
    //   record if disposition==='attachment'
    //   OR (disposition in {'','inline'} AND filename!==null)
    // This excludes: cid inline images (inline + no filename), detached sigs (no filename,
    // not explicit attachment), plain text/html body parts (empty disposition, no filename).
    const isAttachment =
      disposition === 'attachment' ||
      ((disposition === '' || disposition === 'inline') && filename !== null);

    if (!isAttachment) return;

    if (collected.length >= MAX_ATTACHMENTS_PER_MESSAGE) {
      truncated = true;
      return;
    }

    collected.push({
      filename,
      mimeType: mime,
      size: n.size ?? 0,
      partId: n.part ?? '',
      md5: n.md5 ?? null,
    });
  }

  walk(msg.bodyStructure);

  return { attachments: collected, truncated };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Resolve the filename for a node with this precedence:
 *   1. dispositionParameters.filename (RFC 2183)
 *   2. parameters.name (old Outlook / RFC 2045 fallback)
 *   3. For message/rfc822: envelope.subject
 *   4. null
 *
 * The typeof guard protects against a pathological RFC 2231 partial continuation
 * leaving an object instead of a string (CONTEXT: edge-case T16).
 * Do NOT re-decode — imapflow already RFC-2047/2231-decoded these values (tools.js:632/704/722).
 */
function resolveFilename(n: MessageStructureObject): string | null {
  const fromDisp = n.dispositionParameters?.['filename'];
  if (typeof fromDisp === 'string' && fromDisp) return fromDisp;

  const fromParams = n.parameters?.['name'];
  if (typeof fromParams === 'string' && fromParams) return fromParams;

  // rfc822 fallback: envelope subject (Locked Decision 4)
  if ((n.type ?? '').toLowerCase() === 'message/rfc822') {
    const subject = n.envelope?.subject;
    if (typeof subject === 'string' && subject) return subject;
  }

  return null;
}
