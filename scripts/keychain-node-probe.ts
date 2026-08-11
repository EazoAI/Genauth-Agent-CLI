import { KeychainSecretStore } from "../src/storage/secret-store.js";

const operation = process.argv[2];
const reference = process.argv[3];
if (!operation || !reference) throw new Error("usage: keychain-node-probe <set|get|delete> <reference>");
const store = new KeychainSecretStore();
if (operation === "set") await store.set(reference, "agent-identity-keychain-compat-probe");
else if (operation === "get") {
  if (await store.get(reference) !== "agent-identity-keychain-compat-probe") throw new Error("unexpected probe value");
} else if (operation === "delete") await store.delete(reference);
else throw new Error("unknown operation");
process.stdout.write("ok\n");
