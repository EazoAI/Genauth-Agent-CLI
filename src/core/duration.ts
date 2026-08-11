const durationPattern = /^(\d+(?:\.\d+)?)(ms|s|m|h)$/u;

export function parseDurationMs(value: string): number {
  const match = durationPattern.exec(value.trim());
  if (!match) {
    throw new Error("duration must use ms, s, m, or h");
  }
  const amount = Number(match[1]);
  const unit = match[2];
  const multiplier = unit === "ms" ? 1 : unit === "s" ? 1_000 : unit === "m" ? 60_000 : 3_600_000;
  const result = Math.round(amount * multiplier);
  if (!Number.isSafeInteger(result) || result <= 0) {
    throw new Error("duration must be positive");
  }
  return result;
}

export function durationSeconds(value: string): number {
  return Math.round(parseDurationMs(value) / 1_000);
}
