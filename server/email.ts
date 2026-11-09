import nodemailer from "nodemailer";
import { config } from "./config.js";

const transport = config.SMTP_HOST
  ? nodemailer.createTransport({
      host: config.SMTP_HOST,
      port: config.SMTP_PORT,
      secure: config.SMTP_SECURE,
      auth: config.SMTP_USER ? { user: config.SMTP_USER, pass: config.SMTP_PASSWORD } : undefined
    })
  : null;

async function deliver(to: string, subject: string, text: string, html: string) {
  if (!transport) {
    if (config.NODE_ENV === "production") throw new Error("SMTP is required in production");
    console.info("[development email]", { to, subject, text });
    return;
  }
  await transport.sendMail({ from: config.EMAIL_FROM, to, subject, text, html });
}

export function sendVerificationEmail(to: string, url: string) {
  return deliver(to, "Verify your OCodeJS account",
    `Verify your email address: ${url}\nThis link expires in 30 minutes.`,
    `<p>Verify your email address to activate your OCodeJS account.</p><p><a href="${url}">Verify email</a></p><p>This link expires in 30 minutes.</p>`);
}

export function sendPasswordResetEmail(to: string, url: string) {
  return deliver(to, "Reset your OCodeJS password",
    `Reset your password: ${url}\nThis link expires in 30 minutes. If you did not request this, ignore this email.`,
    `<p>A password reset was requested for your account.</p><p><a href="${url}">Reset password</a></p><p>This link expires in 30 minutes. If you did not request this, ignore this email.</p>`);
}
