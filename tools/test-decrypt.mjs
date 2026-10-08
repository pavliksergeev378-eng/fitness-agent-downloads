import fs from "node:fs";
import { createHash, webcrypto } from "node:crypto";
globalThis.crypto ??= webcrypto;
const { decryptPayload } = await import("../docs/app.js");
const [encryptedPath, passwordPath, originalPath] = process.argv.slice(2);
if (!encryptedPath || !passwordPath || !originalPath) {
  throw new Error("Usage: node tools/test-decrypt.mjs <encrypted> <password-file> <original-apk>");
}
const data = fs.readFileSync(encryptedPath);
const key = fs.readFileSync(passwordPath, "utf8").trimEnd();
const plain = Buffer.from(await decryptPayload(data, key));
const expected = createHash("sha256").update(fs.readFileSync(originalPath)).digest("hex");
const actual = createHash("sha256").update(plain).digest("hex");
if (actual !== expected) throw new Error("Decrypted APK hash does not match");
let badKeyRejected = false;
try { await decryptPayload(data, "wrong-key"); } catch { badKeyRejected = true; }
if (!badKeyRejected) throw new Error("Wrong key unexpectedly succeeded");
process.stdout.write("Encrypted browser download passed: " + actual + "\n");