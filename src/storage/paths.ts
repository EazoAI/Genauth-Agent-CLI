import os from "node:os";
import path from "node:path";

export function userConfigDirectory(
  environment: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  homeDirectory = os.homedir()
): string {
  const override = environment.GENAUTH_AGENT_CONFIG_DIR?.trim();
  if (override) {
    return override;
  }
  if (platform === "win32") {
    const appData = environment.APPDATA?.trim();
    if (!appData) {
      throw new Error("APPDATA is not configured");
    }
    return path.join(appData, "genauth-agent");
  }
  if (platform === "darwin") {
    return path.join(homeDirectory, "Library", "Application Support", "genauth-agent");
  }
  const xdg = environment.XDG_CONFIG_HOME?.trim();
  return path.join(xdg || path.join(homeDirectory, ".config"), "genauth-agent");
}
