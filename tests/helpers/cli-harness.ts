import http from "node:http";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Readable, Writable } from "node:stream";
import { Agent } from "undici";
import { AppContext } from "../../src/cli/context.js";
import { createProgram } from "../../src/cli/create-program.js";
import { ProfileStore } from "../../src/storage/profile-store.js";
import { MemorySecretStore } from "../../src/storage/secret-store.js";

export interface RecordedRequest {
  method: string;
  path: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

export interface Harness {
  endpoint: string;
  profileStore: ProfileStore;
  secrets: MemorySecretStore;
  requests: RecordedRequest[];
  run: (arguments_: string[], input?: string) => Promise<{ stdout: string; stderr: string }>;
  close: () => Promise<void>;
}

export async function createHarness(options: {
  loginType?: "user" | "tenant_admin";
  handler?: (request: RecordedRequest, response: http.ServerResponse) => void;
} = {}): Promise<Harness> {
  const requests: RecordedRequest[] = [];
  const server = http.createServer((incoming, response) => {
    const chunks: Buffer[] = [];
    incoming.on("data", chunk => chunks.push(Buffer.from(chunk)));
    incoming.on("end", () => {
      const recorded = {
        method: incoming.method ?? "",
        path: incoming.url ?? "",
        headers: incoming.headers,
        body: Buffer.concat(chunks).toString("utf8")
      };
      requests.push(recorded);
      if (options.handler) options.handler(recorded, response);
      else { response.setHeader("Content-Type", "application/json"); response.end('{"data":{}}'); }
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fixture server unavailable");
  const endpoint = `http://127.0.0.1:${address.port}`;
  const directory = await mkdtemp(path.join(os.tmpdir(), "agent-identity-node-test-"));
  const profileStore = new ProfileStore(path.join(directory, "config.json"));
  const secrets = new MemorySecretStore();
  await profileStore.save({
    api_version: "agent-identity.cli/v1",
    current_profile: "test",
    profiles: {
      test: {
        endpoint,
        client_id: "client-1",
        login_type: options.loginType ?? "tenant_admin",
        subject_id: options.loginType === "user" ? "user-1" : "admin-1",
        selected_user_pool_id: "pool-1",
        secret_ref: "keychain://agent-identity/session/test"
      }
    }
  });
  await secrets.set("keychain://agent-identity/session/test", JSON.stringify({ access_token: "human-token" }));
  const dispatcher = new Agent();
  return {
    endpoint,
    profileStore,
    secrets,
    requests,
    async run(arguments_, input = "") {
      const stdout = new Collector();
      const stderr = new Collector();
      const app = new AppContext({
        profiles: profileStore,
        secrets,
        dispatcher,
        io: { input: Readable.from([input]), output: stdout, error: stderr }
      });
      const { program } = createProgram(app);
      await program.parseAsync(["node", "agent-identity", "--non-interactive", ...arguments_]);
      return { stdout: stdout.value, stderr: stderr.value };
    },
    async close() {
      await dispatcher.close();
      await new Promise<void>(resolve => server.close(() => resolve()));
      await rm(directory, { recursive: true, force: true });
    }
  };
}

class Collector extends Writable {
  value = "";
  override _write(chunk: Buffer | string, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.value += chunk.toString();
    callback();
  }
}
