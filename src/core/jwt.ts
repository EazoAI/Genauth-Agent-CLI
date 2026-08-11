export interface JwtInspection {
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
}

export function inspectJwt(serialized: string): JwtInspection {
  const parts = serialized.split(".");
  if (parts.length !== 3) {
    throw new Error("token must be a compact JWT");
  }
  return {
    header: decodePart(parts[0] ?? ""),
    claims: decodePart(parts[1] ?? "")
  };
}

export function tokenSubject(serialized: string): string {
  try {
    const subject = inspectJwt(serialized).claims.sub;
    return typeof subject === "string" ? subject : "";
  } catch {
    return "";
  }
}

function decodePart(value: string): Record<string, unknown> {
  try {
    const decoded: unknown = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
    if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
      throw new Error("invalid JSON object");
    }
    return decoded as Record<string, unknown>;
  } catch {
    throw new Error("token contains invalid JSON or base64url");
  }
}
