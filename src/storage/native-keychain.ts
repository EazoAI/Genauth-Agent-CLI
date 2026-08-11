import { Entry } from "@napi-rs/keyring";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import {
  decodeGoKeyringValue,
  encodeGoKeyringValue,
  InvalidSecretReferenceError,
  secretAccount,
  type SecretStore
} from "./secret-store.js";

const service = "agent-identity-cli";
const execFileAsync = promisify(execFile);

export function createPlatformSecretStore(platform: NodeJS.Platform): SecretStore {
  if (platform === "darwin") return new MacOsKeychainSecretStore();
  if (platform === "win32") return new WindowsCredentialManagerSecretStore();
  return new NativeKeychainSecretStore();
}

class NativeKeychainSecretStore implements SecretStore {
  async set(reference: string, value: string): Promise<void> {
    if (value === "") throw new InvalidSecretReferenceError();
    new Entry(service, secretAccount(reference)).setPassword(value);
  }

  async get(reference: string): Promise<string> {
    const value = new Entry(service, secretAccount(reference)).getPassword();
    if (!value) throw new Error("secret not found");
    return value;
  }

  async delete(reference: string): Promise<void> {
    new Entry(service, secretAccount(reference)).deleteCredential();
  }
}

class MacOsKeychainSecretStore implements SecretStore {
  async set(reference: string, value: string): Promise<void> {
    if (value === "") throw new InvalidSecretReferenceError();
    const account = secretAccount(reference);
    const encoded = encodeGoKeyringValue(value);
    const command = `add-generic-password -U -s ${shellQuote(service)} -a ${shellQuote(account)} -w ${shellQuote(encoded)}\n`;
    await runSecurityInteractive(command);
  }

  async get(reference: string): Promise<string> {
    const account = secretAccount(reference);
    const { stdout } = await execFileAsync("/usr/bin/security", ["find-generic-password", "-s", service, "-wa", account], {
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
      timeout: 15_000
    });
    return decodeGoKeyringValue(stdout.trim());
  }

  async delete(reference: string): Promise<void> {
    const account = secretAccount(reference);
    await execFileAsync("/usr/bin/security", ["delete-generic-password", "-s", service, "-a", account], {
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
      timeout: 15_000
    });
  }
}

export type WindowsCredentialRunner = (
  action: "set" | "get" | "delete",
  payload: { target: string; username: string; value_base64?: string }
) => Promise<string>;

export class WindowsCredentialManagerSecretStore implements SecretStore {
  constructor(private readonly run: WindowsCredentialRunner = runWindowsCredentialManager) {}

  async set(reference: string, value: string): Promise<void> {
    if (value === "") throw new InvalidSecretReferenceError();
    const account = secretAccount(reference);
    await this.run("set", {
      target: windowsCredentialTarget(account),
      username: account,
      value_base64: Buffer.from(value, "utf8").toString("base64")
    });
  }

  async get(reference: string): Promise<string> {
    const account = secretAccount(reference);
    const encoded = await this.run("get", { target: windowsCredentialTarget(account), username: account });
    if (encoded === "") throw new Error("secret not found");
    return Buffer.from(encoded, "base64").toString("utf8");
  }

  async delete(reference: string): Promise<void> {
    const account = secretAccount(reference);
    await this.run("delete", { target: windowsCredentialTarget(account), username: account });
  }
}

export function windowsCredentialTarget(account: string): string {
  return `${service}:${account}`;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

async function runSecurityInteractive(input: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn("/usr/bin/security", ["-i"], { stdio: ["pipe", "ignore", "pipe"], shell: false });
    let errorOutput = "";
    const timer = setTimeout(() => { child.kill("SIGKILL"); }, 15_000);
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", chunk => { errorOutput += String(chunk); });
    child.once("error", error => { clearTimeout(timer); reject(error); });
    child.once("exit", code => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(errorOutput.trim() || `security exited with ${code ?? 1}`));
    });
    child.stdin.end(input);
  });
}

async function runWindowsCredentialManager(
  action: "set" | "get" | "delete",
  payload: { target: string; username: string; value_base64?: string }
): Promise<string> {
  const encodedCommand = Buffer.from(windowsCredentialPowerShell, "utf16le").toString("base64");
  return runPowerShell([
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-EncodedCommand",
    encodedCommand
  ], JSON.stringify({ action, ...payload }));
}

async function runPowerShell(arguments_: string[], input: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn("powershell.exe", arguments_, {
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
      windowsHide: true
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(stdout.trim());
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(new Error("Windows Credential Manager operation timed out"));
    }, 15_000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", chunk => {
      stdout += String(chunk);
      if (stdout.length > 1024 * 1024) {
        child.kill("SIGKILL");
        finish(new Error("Windows Credential Manager output exceeded the limit"));
      }
    });
    child.stderr.on("data", chunk => {
      stderr += String(chunk);
      if (stderr.length > 1024 * 1024) {
        child.kill("SIGKILL");
        finish(new Error("Windows Credential Manager error output exceeded the limit"));
      }
    });
    child.once("error", error => finish(error));
    child.once("exit", code => {
      if (code === 0) finish();
      else finish(new Error(stderr.trim() || `powershell.exe exited with ${code ?? 1}`));
    });
    child.stdin.end(input);
  });
}

export const windowsCredentialPowerShell = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class GoKeyringCredential {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  private struct CREDENTIAL {
    public UInt32 Flags;
    public UInt32 Type;
    [MarshalAs(UnmanagedType.LPWStr)]
    public string TargetName;
    [MarshalAs(UnmanagedType.LPWStr)]
    public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public UInt32 CredentialBlobSize;
    public IntPtr CredentialBlob;
    public UInt32 Persist;
    public UInt32 AttributeCount;
    public IntPtr Attributes;
    [MarshalAs(UnmanagedType.LPWStr)]
    public string TargetAlias;
    [MarshalAs(UnmanagedType.LPWStr)]
    public string UserName;
  }

  [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern bool CredWrite(ref CREDENTIAL credential, UInt32 flags);

  [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern bool CredRead(string target, UInt32 type, UInt32 flags, out IntPtr credential);

  [DllImport("Advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern bool CredDelete(string target, UInt32 type, UInt32 flags);

  [DllImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = false)]
  private static extern void CredFree(IntPtr buffer);

  public static void Write(string target, string username, byte[] value) {
    IntPtr blob = Marshal.AllocHGlobal(value.Length);
    try {
      Marshal.Copy(value, 0, blob, value.Length);
      CREDENTIAL credential = new CREDENTIAL {
        Type = 1,
        TargetName = target,
        CredentialBlobSize = (UInt32)value.Length,
        CredentialBlob = blob,
        Persist = 2,
        UserName = username
      };
      if (!CredWrite(ref credential, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
    } finally {
      for (int index = 0; index < value.Length; index++) Marshal.WriteByte(blob, index, 0);
      Marshal.FreeHGlobal(blob);
      Array.Clear(value, 0, value.Length);
    }
  }

  public static byte[] Read(string target) {
    IntPtr pointer;
    if (!CredRead(target, 1, 0, out pointer)) throw new Win32Exception(Marshal.GetLastWin32Error());
    try {
      CREDENTIAL credential = (CREDENTIAL)Marshal.PtrToStructure(pointer, typeof(CREDENTIAL));
      byte[] value = new byte[credential.CredentialBlobSize];
      if (value.Length > 0) Marshal.Copy(credential.CredentialBlob, value, 0, value.Length);
      return value;
    } finally {
      CredFree(pointer);
    }
  }

  public static void Delete(string target) {
    if (!CredDelete(target, 1, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
  }
}
'@

$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
switch ([string]$payload.action) {
  'set' {
    [byte[]]$value = [Convert]::FromBase64String([string]$payload.value_base64)
    [GoKeyringCredential]::Write([string]$payload.target, [string]$payload.username, $value)
  }
  'get' {
    [byte[]]$value = [GoKeyringCredential]::Read([string]$payload.target)
    try { [Console]::Out.Write([Convert]::ToBase64String($value)) }
    finally { [Array]::Clear($value, 0, $value.Length) }
  }
  'delete' { [GoKeyringCredential]::Delete([string]$payload.target) }
  default { throw 'unsupported credential action' }
}
`;
