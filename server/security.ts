import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { config } from "./config.js";

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function createCsrfToken(): string {
  const nonce = randomToken(24);
  const signature = createHmac("sha256", config.CSRF_SECRET).update(nonce).digest("base64url");
  return nonce + "." + signature;
}

export function isValidCsrfToken(token: string): boolean {
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return false;
  const expected = createHmac("sha256", config.CSRF_SECRET).update(parts[0]).digest();
  let actual: Buffer;
  try {
    actual = Buffer.from(parts[1], "base64url");
  } catch {
    return false;
  }
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
