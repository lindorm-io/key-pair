import { Algorithm, KeyType } from "../enum";
import { generateKeyPair } from "crypto";
import { getRandomValue } from "@lindorm-io/core";

const MODULUS_LENGTH = 4096;
const KEY_ENCODING = "pkcs1";
const KEY_FORMAT = "pem";
const PRIVATE_KEY_CIPHER = "aes-256-cbc";

export interface IGenerateRSAKeysData {
  algorithm: string;
  passphrase: string;
  privateKey: string;
  publicKey: string;
  type: string;
}

export const generateRSAKeys = async (passphrase: string = getRandomValue(64)): Promise<IGenerateRSAKeysData> => {
  return new Promise((resolve, reject) => {
    generateKeyPair(
      KeyType.RSA,
      {
        modulusLength: MODULUS_LENGTH,
        publicKeyEncoding: {
          type: KEY_ENCODING,
          format: KEY_FORMAT,
        },
        privateKeyEncoding: {
          type: KEY_ENCODING,
          format: KEY_FORMAT,
          cipher: PRIVATE_KEY_CIPHER,
          passphrase,
        },
      },
      (err, publicKey, privateKey) => {
        if (err) {
          reject(err);
        }
        resolve({
          algorithm: Algorithm.RS512,
          passphrase,
          privateKey,
          publicKey,
          type: KeyType.RSA,
        });
      },
    );
  });
};
