import { pool } from "./db.js";
import { hashToken, randomToken } from "./security.js";

export type AccountTokenPurpose = "email_verification" | "password_reset";

export async function issueAccountToken(userId: string, purpose: AccountTokenPurpose) {
  const token = randomToken(32);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const user = await client.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [userId]);
    if (!user.rowCount) throw new Error("Cannot issue account token for an unknown user");
    await client.query(
      "UPDATE account_action_tokens SET consumed_at=now() WHERE user_id=$1 AND purpose=$2 AND consumed_at IS NULL",
      [userId, purpose]
    );
    await client.query(
      "INSERT INTO account_action_tokens(user_id,token_hash,purpose,expires_at) VALUES($1,$2,$3,now()+interval '30 minutes')",
      [userId, hashToken(token), purpose]
    );
    await client.query("COMMIT");
    return token;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export async function consumeAccountToken(token: string, purpose: AccountTokenPurpose) {
  const result = await pool.query<{ user_id: string }>(
    `UPDATE account_action_tokens SET consumed_at=now()
      WHERE token_hash=$1 AND purpose=$2 AND consumed_at IS NULL AND expires_at>now()
      RETURNING user_id`,
    [hashToken(token), purpose]
  );
  return result.rows[0]?.user_id ?? null;
}
