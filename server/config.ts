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
  COOKIE_DOMAIN: z.string().optional().default(""),
  SESSION_TTL_SECONDS: z.coerce.number().int().min(300).max(2592000).default(604800)
});

const parsed = envSchema.safeParse(process.env);
if (!parsed.success) {
  console.error("Invalid environment configuration:", parsed.error.flatten().fieldErrors);
  throw new Error("Invalid environment configuration");
}

export const config = {
  ...parsed.data,
  webOrigins: parsed.data.WEB_ORIGINS.split(",").map((v) => v.trim()).filter(Boolean),
  secureCookies: parsed.data.NODE_ENV === "production"
};
