// Thin local type shim for mailparser (ships no own types, no @types package).
// Covers only the surface imap.ts uses: simpleParser() -> { attachments }.
// v2.6.0 P-2 typecheck layer — see tsconfig.typecheck.json.
declare module 'mailparser' {
  export interface Attachment {
    filename?: string;
    contentType?: string;
    size?: number;
    [key: string]: unknown;
  }
  export interface ParsedMail {
    attachments?: Attachment[];
    text?: string;
    html?: string | false;
    subject?: string;
    [key: string]: unknown;
  }
  export function simpleParser(
    source: Buffer | string | NodeJS.ReadableStream,
    options?: unknown,
  ): Promise<ParsedMail>;
}
