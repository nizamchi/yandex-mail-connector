// Verified against nodemailer v9.0.1 + @types/nodemailer v6.4.23 .d.ts on 2026-06-22.
// createTransport/sendMail options and the OAuth2 auth shape are unchanged from
// v6-v8 usage; the v8->v9 major bump (security advisories: CRLF List-* header
// injection, OAuth2 TLS) required no API changes to this core send path.
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
    auth: creds.password
      ? { user: creds.email, pass: creds.password }
      : { type: 'OAuth2', user: creds.email, accessToken: creds.oauthToken! },
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
