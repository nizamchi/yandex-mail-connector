// attachment-select.ts -- pure attachment selector shared by getAttachmentBytes
// (imap.ts) and its unit tests. Dependency-free on purpose so tests need no live
// IMAP / mailparser bundle.
//
// Contract:
//   filename -- when provided, selects by exact filename first, then
//               case-insensitive substring. Takes PRECEDENCE over index.
//   index    -- 0-based position into the attachment list; used only when
//               filename is absent. Defaults to 0 (first attachment).
//
// Rationale: yandex_get_attachment's schema defaults `index` to 0, so a
// previous "index first" dispatch made the filename branch unreachable. Checking
// filename first restores by-name selection while keeping index as the default.

export interface AttachmentSelector {
  index?: number;
  filename?: string;
}

export function selectAttachment<T extends { filename?: string }>(
  attachments: readonly T[],
  selector: AttachmentSelector,
): T | undefined {
  if (selector.filename) {
    const needle = selector.filename;
    return (
      attachments.find(a => a.filename === needle) ??
      attachments.find(
        a =>
          typeof a.filename === 'string' &&
          a.filename.toLowerCase().includes(needle.toLowerCase()),
      )
    );
  }
  return attachments[selector.index ?? 0];
}
