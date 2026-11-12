#!/usr/bin/env node
/**
 * gen-keys.js — one-time ed25519 keypair generator for NEAR testnet accounts.
 * no external deps: uses node:crypto only.
 *
 * usage:
 *   node scripts/gen-keys.js            # one keypair
 *   node scripts/gen-keys.js --count 3  # three keypairs
 *
 * after generating:
 *   1. create a funded account on testnet (e.g. via https://near-faucet.io)
 *   2. import the key: near account import-account <id> --use-master-pair ...
 *      or write the JSON keyfile to ~/.near-credentials/testnet/<id>.json
 *   3. put the secret key into .env as SHEARPIN_OWNER_KEY
 */
import { generateKeyPairSync } from "node:crypto";

const count = process.argv.includes("--count")
  ? Number(process.argv[process.argv.indexOf("--count") + 1] ?? 1)
  : 1;

function base58Encode(bytes) {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = BigInt("0x" + Buffer.from(bytes).toString("hex"));
  let out = "";
  while (num > 0n) {
    out = ALPHABET[Number(num % 58n)] + out;
    num /= 58n;
  }
  // leading zero bytes -> '1'
  for (const b of bytes) {
    if (b === 0) out = "1" + out;
    else break;
  }
  return out;
}

for (let i = 0; i < count; i++) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pubRaw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  const secRaw = privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32);
  console.log(JSON.stringify({
    public_key: `ed25519:${base58Encode(pubRaw)}`,
    secret_key: `ed25519:${base58Encode(Buffer.concat([secRaw, pubRaw]))}`,
  }));
}