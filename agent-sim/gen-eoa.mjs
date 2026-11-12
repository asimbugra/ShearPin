/** generate a fresh EOA address for the Sepolia success tx */
import { generateKeyPairSync } from "node:crypto";
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
// not used for eth; just get a random eth address via ethers
import { ethers } from "ethers";
const wallet = ethers.Wallet.createRandom();
console.log("NEW EOA:", wallet.address);
console.log("PRIV (keep secret):", wallet.privateKey);
