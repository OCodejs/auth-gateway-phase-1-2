import "dotenv/config";
import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  HOST: z.string().default("0.0.0.0"),
  PORT: z.coerce.number().int().positive().default(3000),
  DATABASE_URL: z.string().min(1),
  SESSION_SECRET: z.string().min(32),
  CSRF_SECRET: z.string().min(32),
  WEB_ORIGINS: z.string().default("http://localhost:3000"),
  APP_BASE_URL: z.string().url().default("http://localhost:3000"),
  COOKIE_DOMAIN: z.string().optional().default(""),
  SESSION_TTL_SECONDS: z.coerce.number().int().min(300).max(2592000).default(604800),
  TRUST_PROXY_HOPS: z.coerce.number().int().min(0).max(10).default(0),
  SMTP_HOST: z.string().optional().default(""),
  SMTP_PORT: z.coerce.number().int().positive().default(587),
  SMTP_SECURE: z.string().default("false").transform((value) => value.toLowerCase() === "true"),
  SMTP_USER: z.string().optional().default(""),
  SMTP_PASSWORD: z.string().optional().default(""),
  EMAIL_FROM: z.string().email().default("no-reply@example.com")
}).superRefine((value, ctx) => {
  if (value.NODE_ENV === "production" && !value.SMTP_HOST) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["SMTP_HOST"], message: "SMTP_HOST is required in production" });
  }
  if (Boolean(value.SMTP_USER) !== Boolean(value.SMTP_PASSWORD)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["SMTP_USER"], message: "SMTP_USER and SMTP_PASSWORD must be configured together" });
  }
  if (value.WEB_ORIGINS.split(",").map((origin) => origin.trim()).filter(Boolean).length === 0) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["WEB_ORIGINS"], message: "At least one browser origin is required" });
  }
});

const parsed = envSchema.safeParse(process.env);
if (!parsed.success) {
  console.error("Invalid environment configuration:", parsed.error.flatten().fieldErrors);
  throw new Error("Invalid environment configuration");
}

export const config = {
  ...parsed.data,
  webOrigins: parsed.data.WEB_ORIGINS.split(",").map((value) => value.trim()).filter(Boolean),
  secureCookies: parsed.data.NODE_ENV === "production"
};
