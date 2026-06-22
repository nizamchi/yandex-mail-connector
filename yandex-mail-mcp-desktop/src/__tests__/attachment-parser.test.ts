// attachment-parser.test.ts -- edge-case unit tests for extractAttachments (Phase 1, plan 01-01).
//
// All fixtures are shaped as MessageStructureObject from imap-flow.d.ts:417-448.
// The rfc822 fixtures use the SYNTHETIC childNodes shape (tools.js:807-826).
// No IMAP access, no downloads, pure metadata-only.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  extractAttachments,
  MAX_ATTACHMENTS_PER_MESSAGE,
  type ParsedAttachment,
} from '../attachment-parser.js';

import type { FetchMessageObject, MessageStructureObject } from 'imapflow';

// ── Helpers ───────────────────────────────────────────────────────────

/** Build a minimal FetchMessageObject with an optional bodyStructure. */
function msg(bodyStructure?: MessageStructureObject): FetchMessageObject {
  return { seq: 1, uid: 100, bodyStructure } as FetchMessageObject;
}

/** Build a leaf node (no childNodes). Accepts partial overrides. */
function leaf(overrides: Partial<MessageStructureObject> & { type: string }): MessageStructureObject {
  return { ...overrides };
}

// ── T01: No bodyStructure ──────────────────────────────────────────────

test('T01: no bodyStructure returns empty attachments without throwing', () => {
  const result = extractAttachments(msg());
  assert.deepStrictEqual(result.attachments, []);
  assert.strictEqual(result.truncated, false);
});

test('T01b: bodyStructure explicitly undefined returns empty attachments', () => {
  const result = extractAttachments({ seq: 1, uid: 1 } as FetchMessageObject);
  assert.deepStrictEqual(result.attachments, []);
  assert.strictEqual(result.truncated, false);
});

// ── T02: Minimal node (no filename, no disposition) ────────────────────

test('T02: minimal { type: "application/pdf" } node is excluded (no filename)', () => {
  const result = extractAttachments(msg(leaf({ type: 'application/pdf' })));
  assert.deepStrictEqual(result.attachments, []);
});

// ── T03: Flat single-part text/plain ────────────────────────────────────

test('T03: flat text/plain root leaf not recorded (no filename, disposition empty)', () => {
  const result = extractAttachments(msg(leaf({ type: 'text/plain', size: 1024 })));
  assert.deepStrictEqual(result.attachments, []);
});

// ── T04: multipart/alternative (text + html) ────────────────────────────

test('T04: multipart/alternative container walked, no leaves recorded', () => {
  const structure: MessageStructureObject = {
    type: 'multipart/alternative',
    childNodes: [
      leaf({ type: 'text/plain', part: '1', size: 300 }),
      leaf({ type: 'text/html', part: '2', size: 800 }),
    ],
  };
  const result = extractAttachments(msg(structure));
  assert.deepStrictEqual(result.attachments, []);
});

// ── T05: multipart/related nested >= 2 deep ────────────────────────────

test('T05a: inline image with no filename (cid) inside related is excluded', () => {
  const structure: MessageStructureObject = {
    type: 'multipart/alternative',
    childNodes: [
      leaf({ type: 'text/plain', part: '1' }),
      {
        type: 'multipart/related',
        childNodes: [
          leaf({ type: 'text/html', part: '2.1' }),
          leaf({
            type: 'image/png',
            part: '2.2',
            disposition: 'inline',
            id: '<cid123@example.com>',
            size: 4096,
          }),
        ],
      },
    ],
  };
  const result = extractAttachments(msg(structure));
  assert.deepStrictEqual(result.attachments, []);
});

test('T05b: named leaf >= 2 levels deep is recorded', () => {
  const structure: MessageStructureObject = {
    type: 'multipart/mixed',
    childNodes: [
      leaf({ type: 'text/plain', part: '1' }),
      {
        type: 'multipart/related',
        childNodes: [
          leaf({ type: 'text/html', part: '2.1' }),
          leaf({
            type: 'image/png',
            part: '2.2',
            disposition: 'inline',
            dispositionParameters: { filename: 'logo.png' },
            size: 8192,
          }),
        ],
      },
    ],
  };
  const result = extractAttachments(msg(structure));
  assert.strictEqual(result.attachments.length, 1);
  assert.strictEqual(result.attachments[0].filename, 'logo.png');
  assert.strictEqual(result.attachments[0].mimeType, 'image/png');
  assert.strictEqual(result.attachments[0].partId, '2.2');
});

// ── T06: multipart/signed ──────────────────────────────────────────────

test('T06: multipart/signed: named attachment recorded; detached sig (no filename) excluded', () => {
  const structure: MessageStructureObject = {
    type: 'multipart/signed',
    childNodes: [
      {
        type: 'multipart/mixed',
        childNodes: [
          leaf({ type: 'text/plain', part: '1.1' }),
          leaf({
            type: 'application/pdf',
            part: '1.2',
            disposition: 'attachment',
            dispositionParameters: { filename: 'contract.pdf' },
            size: 51200,
          }),
        ],
      },
      leaf({
        type: 'application/pgp-signature',
        part: '2',
        size: 832,
      }),
    ],
  };
  const result = extractAttachments(msg(structure));
  assert.strictEqual(result.attachments.length, 1);
  assert.strictEqual(result.attachments[0].filename, 'contract.pdf');
  assert.strictEqual(result.attachments[0].mimeType, 'application/pdf');
});

// ── T07: multipart/mixed with disposition=attachment PDF ───────────────

test('T07: disposition=attachment PDF in multipart/mixed is recorded', () => {
  const structure: MessageStructureObject = {
    type: 'multipart/mixed',
    childNodes: [
      leaf({ type: 'text/plain', part: '1' }),
      leaf({
        type: 'application/pdf',
        part: '2',
        disposition: 'attachment',
        dispositionParameters: { filename: 'invoice.pdf' },
        size: 102400,
        md5: 'abc123',
      }),
    ],
  };
  const result = extractAttachments(msg(structure));
  assert.strictEqual(result.attachments.length, 1);
  const att = result.attachments[0];
  assert.strictEqual(att.filename, 'invoice.pdf');
  assert.strictEqual(att.mimeType, 'application/pdf');
  assert.strictEqual(att.size, 102400);
  assert.strictEqual(att.partId, '2');
  assert.strictEqual(att.md5, 'abc123');
});

// ── T08: disposition=attachment with NO filename ───────────────────────

test('T08: disposition=attachment with no filename is recorded with filename null', () => {
  const structure: MessageStructureObject = {
    type: 'multipart/mixed',
    childNodes: [
      leaf({ type: 'text/plain', part: '1' }),
      leaf({
        type: 'application/octet-stream',
        part: '2',
        disposition: 'attachment',
        size: 2048,
      }),
    ],
  };
  const result = extractAttachments(msg(structure));
  assert.strictEqual(result.attachments.length, 1);
  assert.strictEqual(result.attachments[0].filename, null);
});

// ── T09: disposition absent + parameters.name present (old Outlook) ────

test('T09: parameters.name fallback for old Outlook without explicit disposition', () => {
  const structure: MessageStructureObject = {
    type: 'multipart/mixed',
    childNodes: [
      leaf({ type: 'text/plain', part: '1' }),
      leaf({
        type: 'application/msword',
        part: '2',
        parameters: { name: 'report.doc' },
        size: 30720,
      }),
    ],
  };
  const result = extractAttachments(msg(structure));
  assert.strictEqual(result.attachments.length, 1);
  assert.strictEqual(result.attachments[0].filename, 'report.doc');
});

// ── T10: message/rfc822 forwarded email (synthetic childNodes) ─────────
// Shape verified against tools.js:807-826: rfc822 nodes get SYNTHETIC childNodes.
// Must be recorded as ONE opaque leaf; inner parts must NOT appear in results.

test('T10: message/rfc822 recorded as one opaque leaf; inner parts not recorded', () => {
  const innerPdf: MessageStructureObject = leaf({
    type: 'application/pdf',
    part: '1.1.2',
    disposition: 'attachment',
    dispositionParameters: { filename: 'inner.pdf' },
    size: 20480,
  });
  const innerText: MessageStructureObject = leaf({
    type: 'text/plain',
    part: '1.1.1',
    size: 512,
  });
  // Synthetic encapsulated message (the child of the rfc822 node)
  const encapsulatedMessage: MessageStructureObject = {
    type: 'multipart/mixed',
    part: '1.1',
    childNodes: [innerText, innerPdf],
  };
  // The rfc822 carrier node — dispositionParameters.filename for the .eml filename
  const rfc822Node: MessageStructureObject = {
    type: 'message/rfc822',
    part: '1',
    disposition: 'attachment',
    dispositionParameters: { filename: 'forwarded.eml' },
    size: 25000,
    childNodes: [encapsulatedMessage],  // synthetic as per tools.js:807-826
  };
  const structure: MessageStructureObject = {
    type: 'multipart/mixed',
    childNodes: [
      leaf({ type: 'text/plain', part: '0' }),
      rfc822Node,
    ],
  };
  const result = extractAttachments(msg(structure));
  // Exactly ONE attachment: the rfc822 carrier; inner parts NOT recorded
  assert.strictEqual(result.attachments.length, 1);
  assert.strictEqual(result.attachments[0].filename, 'forwarded.eml');
  assert.strictEqual(result.attachments[0].mimeType, 'message/rfc822');
  assert.strictEqual(result.attachments[0].partId, '1');
  // Confirm inner parts are absent
  const innerFilenames = result.attachments.map(a => a.filename);
  assert.ok(!innerFilenames.includes('inner.pdf'), 'inner.pdf must not be recorded');
});

test('T10b: message/rfc822 with no dispositionParameters.filename falls back to envelope.subject', () => {
  const rfc822Node: MessageStructureObject = {
    type: 'message/rfc822',
    part: '1',
    envelope: { subject: 'Re: the original subject' } as any,
    size: 12000,
    childNodes: [leaf({ type: 'text/plain', part: '1.1' })],
  };
  const result = extractAttachments(msg(rfc822Node));
  assert.strictEqual(result.attachments.length, 1);
  assert.strictEqual(result.attachments[0].filename, 'Re: the original subject');
});

test('T10c: message/rfc822 with neither filename nor envelope.subject has filename null', () => {
  const rfc822Node: MessageStructureObject = {
    type: 'message/rfc822',
    part: '1',
    size: 5000,
    childNodes: [leaf({ type: 'text/plain', part: '1.1' })],
  };
  const result = extractAttachments(msg(rfc822Node));
  assert.strictEqual(result.attachments.length, 1);
  assert.strictEqual(result.attachments[0].filename, null);
});

// ── T11: Nested forward >= 2 levels ────────────────────────────────────

test('T11: nested forward >= 2 levels: only outermost rfc822 recorded (no recursion into inner)', () => {
  // Outer forward: carries an inner forward
  const deepInnerPdf: MessageStructureObject = leaf({
    type: 'application/pdf',
    part: '1.1.1.2',
    disposition: 'attachment',
    dispositionParameters: { filename: 'deep.pdf' },
    size: 9999,
  });
  const innerForward: MessageStructureObject = {
    type: 'message/rfc822',
    part: '1.1.1',
    dispositionParameters: { filename: 'inner-forward.eml' },
    size: 15000,
    childNodes: [
      {
        type: 'multipart/mixed',
        childNodes: [leaf({ type: 'text/plain' }), deepInnerPdf],
      },
    ],
  };
  const outerForward: MessageStructureObject = {
    type: 'message/rfc822',
    part: '1',
    dispositionParameters: { filename: 'outer-forward.eml' },
    size: 20000,
    childNodes: [innerForward],
  };
  const structure: MessageStructureObject = {
    type: 'multipart/mixed',
    childNodes: [
      leaf({ type: 'text/plain', part: '0' }),
      outerForward,
    ],
  };
  const result = extractAttachments(msg(structure));
  // Only the outermost rfc822 is recorded; inner parts are not
  assert.strictEqual(result.attachments.length, 1);
  assert.strictEqual(result.attachments[0].filename, 'outer-forward.eml');
});

// ── T12: multipart/report (bounce) ─────────────────────────────────────

test('T12: multipart/report: rfc822 recorded as leaf; delivery-status excluded', () => {
  const structure: MessageStructureObject = {
    type: 'multipart/report',
    childNodes: [
      leaf({ type: 'text/plain', part: '1', size: 400 }),
      leaf({ type: 'message/delivery-status', part: '2', size: 200 }),
      {
        type: 'message/rfc822',
        part: '3',
        envelope: { subject: 'Original message' } as any,
        size: 8000,
        childNodes: [
          leaf({ type: 'text/plain', part: '3.1' }),
        ],
      },
    ],
  };
  const result = extractAttachments(msg(structure));
  assert.strictEqual(result.attachments.length, 1);
  assert.strictEqual(result.attachments[0].mimeType, 'message/rfc822');
  assert.strictEqual(result.attachments[0].filename, 'Original message');
});

// ── T13: text/calendar (.ics) ──────────────────────────────────────────

test('T13: text/calendar with parameters.name is recorded', () => {
  const structure: MessageStructureObject = {
    type: 'multipart/mixed',
    childNodes: [
      leaf({ type: 'text/plain', part: '1' }),
      leaf({
        type: 'text/calendar',
        part: '2',
        parameters: { name: 'invite.ics' },
        size: 2048,
      }),
    ],
  };
  const result = extractAttachments(msg(structure));
  assert.strictEqual(result.attachments.length, 1);
  assert.strictEqual(result.attachments[0].filename, 'invite.ics');
  assert.strictEqual(result.attachments[0].mimeType, 'text/calendar');
});

// ── T14: winmail.dat (application/ms-tnef) ────────────────────────────

test('T14: winmail.dat (application/ms-tnef) recorded as-is, not expanded', () => {
  const structure: MessageStructureObject = {
    type: 'multipart/mixed',
    childNodes: [
      leaf({ type: 'text/plain', part: '1' }),
      leaf({
        type: 'application/ms-tnef',
        part: '2',
        disposition: 'attachment',
        dispositionParameters: { filename: 'winmail.dat' },
        size: 65536,
      }),
    ],
  };
  const result = extractAttachments(msg(structure));
  assert.strictEqual(result.attachments.length, 1);
  assert.strictEqual(result.attachments[0].filename, 'winmail.dat');
  assert.strictEqual(result.attachments[0].mimeType, 'application/ms-tnef');
});

// ── T15: inline image with disposition=inline, no filename (cid) ───────

test('T15: inline image with disposition=inline and no filename is excluded', () => {
  const structure: MessageStructureObject = {
    type: 'multipart/related',
    childNodes: [
      leaf({ type: 'text/html', part: '1' }),
      leaf({
        type: 'image/jpeg',
        part: '2',
        disposition: 'inline',
        id: '<photo@example.com>',
        size: 32768,
      }),
    ],
  };
  const result = extractAttachments(msg(structure));
  assert.deepStrictEqual(result.attachments, []);
});

// ── T16: RFC 2231 non-string filename (pathological continuation object) ─

test('T16: non-string dispositionParameters.filename treated as null (no throw)', () => {
  const badNode: MessageStructureObject = {
    type: 'application/pdf',
    part: '1',
    disposition: 'attachment',
    // Pathological: imapflow RFC 2231 partial continuation could leave an object
    dispositionParameters: { filename: { '*0': 'broken', '*1': 'name' } as any },
    size: 4096,
  };
  const result = extractAttachments(msg(badNode));
  // Still recorded (explicit attachment disposition), filename should be null
  assert.strictEqual(result.attachments.length, 1);
  assert.strictEqual(result.attachments[0].filename, null);
});

// ── T17: size=0 is not a skip condition ────────────────────────────────

test('T17: size=0 attachment is still recorded if otherwise qualifies', () => {
  const structure: MessageStructureObject = {
    type: 'multipart/mixed',
    childNodes: [
      leaf({ type: 'text/plain', part: '1' }),
      leaf({
        type: 'application/zip',
        part: '2',
        disposition: 'attachment',
        dispositionParameters: { filename: 'empty.zip' },
        size: 0,
      }),
    ],
  };
  const result = extractAttachments(msg(structure));
  assert.strictEqual(result.attachments.length, 1);
  assert.strictEqual(result.attachments[0].size, 0);
});

// ── T18: UPPERCASE type/disposition casing regression guard ────────────

test('T18: UPPERCASE type and DISPOSITION are handled by parser toLowerCase', () => {
  const structure: MessageStructureObject = {
    type: 'MULTIPART/MIXED',
    childNodes: [
      leaf({ type: 'TEXT/PLAIN', part: '1' }),
      leaf({
        type: 'APPLICATION/PDF',
        part: '2',
        disposition: 'ATTACHMENT',
        dispositionParameters: { filename: 'UPPER.pdf' },
        size: 1000,
      }),
    ],
  };
  const result = extractAttachments(msg(structure));
  assert.strictEqual(result.attachments.length, 1);
  assert.strictEqual(result.attachments[0].mimeType, 'application/pdf');
  assert.strictEqual(result.attachments[0].filename, 'UPPER.pdf');
});

// ── T19: Cyrillic filename passthrough ────────────────────────────────

test('T19: Cyrillic filename passes through verbatim (no re-encode, no =?, no %)', () => {
  const cyrillicName = 'Договор.pdf';
  const structure: MessageStructureObject = {
    type: 'multipart/mixed',
    childNodes: [
      leaf({ type: 'text/plain', part: '1' }),
      leaf({
        type: 'application/pdf',
        part: '2',
        disposition: 'attachment',
        dispositionParameters: { filename: cyrillicName },
        size: 81920,
      }),
    ],
  };
  const result = extractAttachments(msg(structure));
  assert.strictEqual(result.attachments.length, 1);
  const fn = result.attachments[0].filename!;
  assert.strictEqual(fn, cyrillicName);
  assert.ok(!fn.includes('=?'), 'must not contain MIME encoded-word marker =?');
  assert.ok(!fn.includes('%'), 'must not contain percent-encoding');
  assert.ok(!fn.includes('?='), 'must not contain MIME encoded-word end marker ?=');
});

// ── T20: Truncation cap at MAX_ATTACHMENTS_PER_MESSAGE ─────────────────

test('T20: more than MAX_ATTACHMENTS_PER_MESSAGE leaves: result is capped + truncated=true', () => {
  const TOO_MANY = MAX_ATTACHMENTS_PER_MESSAGE + 5;
  const children: MessageStructureObject[] = Array.from({ length: TOO_MANY }, (_, i) =>
    leaf({
      type: 'application/octet-stream',
      part: String(i + 1),
      disposition: 'attachment',
      dispositionParameters: { filename: `file-${i + 1}.bin` },
      size: 100,
    })
  );
  const structure: MessageStructureObject = {
    type: 'multipart/mixed',
    childNodes: children,
  };
  const result = extractAttachments(msg(structure));
  assert.strictEqual(result.attachments.length, MAX_ATTACHMENTS_PER_MESSAGE);
  assert.strictEqual(result.truncated, true);
});

test('T20b: exactly MAX_ATTACHMENTS_PER_MESSAGE leaves: truncated stays false', () => {
  const children: MessageStructureObject[] = Array.from({ length: MAX_ATTACHMENTS_PER_MESSAGE }, (_, i) =>
    leaf({
      type: 'application/octet-stream',
      part: String(i + 1),
      disposition: 'attachment',
      dispositionParameters: { filename: `file-${i + 1}.bin` },
      size: 100,
    })
  );
  const structure: MessageStructureObject = {
    type: 'multipart/mixed',
    childNodes: children,
  };
  const result = extractAttachments(msg(structure));
  assert.strictEqual(result.attachments.length, MAX_ATTACHMENTS_PER_MESSAGE);
  assert.strictEqual(result.truncated, false);
});

// ── T21: md5 capture (Yandex sends null) ──────────────────────────────

test('T21: md5=null on real attachment is captured as null (not missing)', () => {
  const result = extractAttachments(msg(leaf({
    type: 'application/pdf',
    part: '1',
    disposition: 'attachment',
    dispositionParameters: { filename: 'report.pdf' },
    size: 10000,
    md5: undefined,  // Yandex sends null -> imapflow may omit or set undefined
  })));
  assert.strictEqual(result.attachments.length, 1);
  assert.strictEqual(result.attachments[0].md5, null);
});

// ── T22: application/applefile excluded (appledouble resource fork) ────

test('T22: application/applefile leaf is excluded (appledouble over-count guard)', () => {
  const structure: MessageStructureObject = {
    type: 'multipart/appledouble',
    childNodes: [
      leaf({
        type: 'application/applefile',
        part: '1',
        size: 512,
      }),
      leaf({
        type: 'application/pdf',
        part: '2',
        disposition: 'attachment',
        dispositionParameters: { filename: 'document.pdf' },
        size: 50000,
      }),
    ],
  };
  const result = extractAttachments(msg(structure));
  // Only the real PDF is recorded; applefile resource-fork is excluded
  assert.strictEqual(result.attachments.length, 1);
  assert.strictEqual(result.attachments[0].filename, 'document.pdf');
  assert.strictEqual(result.attachments[0].mimeType, 'application/pdf');
});

// ── T23: ParsedAttachment shape validation ────────────────────────────

test('T23: returned ParsedAttachment has exactly the expected fields', () => {
  const result = extractAttachments(msg(leaf({
    type: 'application/pdf',
    part: '2',
    disposition: 'attachment',
    dispositionParameters: { filename: 'shape-check.pdf' },
    size: 5000,
    md5: 'deadbeef',
  })));
  assert.strictEqual(result.attachments.length, 1);
  const att: ParsedAttachment = result.attachments[0];
  // All required fields must be present
  assert.ok('filename' in att);
  assert.ok('mimeType' in att);
  assert.ok('size' in att);
  assert.ok('partId' in att);
  assert.ok('md5' in att);
  assert.strictEqual(typeof att.mimeType, 'string');
  assert.strictEqual(typeof att.size, 'number');
  assert.strictEqual(att.md5, 'deadbeef');
});
