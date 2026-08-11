import { spawn } from "node:child_process";

export function openBrowser(target: string, platform: NodeJS.Platform = process.platform): void {
  const command = platform === "darwin"
    ? { file: "open", arguments: [target] }
    : platform === "win32"
      ? { file: "rundll32", arguments: ["url.dll,FileProtocolHandler", target] }
      : { file: "xdg-open", arguments: [target] };
  const child = spawn(command.file, command.arguments, {
    detached: true,
    stdio: "ignore",
    shell: false,
    windowsHide: true
  });
  child.unref();
}
