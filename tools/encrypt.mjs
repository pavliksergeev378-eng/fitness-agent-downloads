import fs from "node:fs";
import { webcrypto } from "node:crypto";

const [apkPath, passwordPath, outputPath] = process.argv.slice(2);
if (!apkPath || !passwordPath || !outputPath) {
  throw new Error("Usage: node tools/encrypt.mjs <apk> <password-file> <output>");
}
const password = fs.readFileSync(passwordPath, "utf8").trimEnd();
if (password.length < 16) throw new Error("Archive key is too short");

const salt = webcrypto.getRandomValues(new Uint8Array(16));
const iv = webcrypto.getRandomValues(new Uint8Array(12));
const keyMaterial = await webcrypto.subtle.importKey(
  "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
);
const key = await webcrypto.subtle.deriveKey(
  { name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" },
  keyMaterial,
  { name: "AES-GCM", length: 256 },
  false,
  ["encrypt"]
);
const apk = fs.readFileSync(apkPath);
const ciphertext = new Uint8Array(await webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, apk));
const result = Buffer.concat([Buffer.from("FAE1"), Buffer.from(salt), Buffer.from(iv), Buffer.from(ciphertext)]);
fs.writeFileSync(outputPath, result);
process.stdout.write("Encrypted bytes: " + result.length + "\n");