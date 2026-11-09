import { createECDH, createHash, generateKeyPairSync, publicEncrypt } from "node:crypto";

export function makeServerKeys() {
  return generateKeyPairSync("rsa", { modulusLength: 2048 });
}

export function sealForServer(pubPem: string, secret: Buffer): Buffer {
  return publicEncrypt(pubPem, secret);
}

export function handshake() {
  const ecdh = createECDH("prime256v1");
  return ecdh.generateKeys();
}

export async function signInBrowser(data: ArrayBuffer) {
  const key = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  return crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, data);
}

export const etag = (body: string) => createHash("md5").update(body).digest("hex");
