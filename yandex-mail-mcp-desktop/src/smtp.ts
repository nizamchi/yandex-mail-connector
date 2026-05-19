// Verified against nodemailer v8.0.7 + @types/nodemailer v6.4.23 .d.ts on 2026-05-19.
// Options interface (mailer/index.d.ts:98) and OAuth2 auth shape (smtp-connection/xoauth2)
// are byte-compatible with v6 usage. No API changes required for Phase 1.
import nodemailer from 'nodemailer';
import type { Credentials } from './token.js';

export async function sendEmail(
  creds: Credentials,
  params: {
    to: string[];
    cc?: string[];
    bcc?: string[];
    subject: string;
    text?: string;
    html?: string;
    replyTo?: string;
    inReplyTo?: string;
    references?: string[];
  }
): Promise<{ success: boolean; messageId?: string; error?: string }> {
  const transport = nodemailer.createTransport({
    host: creds.smtpHost ?? 'smtp.yandex.com',
    port: 465,
    secure: true,
    auth: { type: 'OAuth2', user: creds.email, accessToken: creds.oauthToken },
  });
  try {
    const info = await transport.sendMail({
      from: creds.email,
      to:  params.to.join(', '),
      cc:  params.cc?.join(', '),
      bcc: params.bcc?.join(', '),
      subject: params.subject,
      text: params.text,
      html: params.html,
      replyTo: params.replyTo,
      inReplyTo: params.inReplyTo,
      references: params.references?.join(' '),
    });
    return { success: true, messageId: info.messageId };
  } catch (e) {
    return { success: false, error: e instanceof Error ? e.message : String(e) };
  }
}
