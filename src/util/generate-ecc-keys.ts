import { Algorithm, KeyType } from "../enum";
import { generateKeyPair } from "crypto";

const NAMED_CURVE = "P-521";
const KEY_FORMAT = "pem";
const KEY_ENCODING_PUBLIC = "spki";
const KEY_ENCODING_PRIVATE = "pkcs8";

export interface IGenerateECCKeysData {
  algorithm: string;
  privateKey: string;
  publicKey: string;
  type: string;
}

export const generateECCKeys = async (): Promise<IGenerateECCKeysData> => {
  return new Promise((resolve, reject) => {
    generateKeyPair(
      KeyType.EC,
      {
        namedCurve: NAMED_CURVE,
        publicKeyEncoding: {
          type: KEY_ENCODING_PUBLIC,
          format: KEY_FORMAT,
        },
        privateKeyEncoding: {
          type: KEY_ENCODING_PRIVATE,
          format: KEY_FORMAT,
        },
      },
      (err, publicKey, privateKey) => {
        if (err) {
          reject(err);
        }
        resolve({
          algorithm: Algorithm.ES512,
          privateKey,
          publicKey,
          type: KeyType.EC,
        });
      },
    );
  });
};
