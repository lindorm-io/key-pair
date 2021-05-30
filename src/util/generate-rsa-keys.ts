import { Algorithm, KeyType } from "../enum";
import { generateKeyPair } from "crypto";

interface IOptions {
  modulusLength?: 1 | 2 | 3 | 4;
  passphrase?: string;
  privateKeyEncoding?: "pkcs1" | "pkcs8";
  publicKeyEncoding?: "pkcs1" | "spki";
}

export interface IGenerateRSAKeysData {
  algorithms: Array<Algorithm>;
  passphrase: string;
  privateKey: string;
  publicKey: string;
  type: KeyType;
}

export const generateRSAKeys = async (options: IOptions = {}): Promise<IGenerateRSAKeysData> => {
  const { modulusLength = 4, passphrase = "", privateKeyEncoding = "pkcs8", publicKeyEncoding = "spki" } = options;

  return new Promise((resolve, reject) => {
    generateKeyPair(
      KeyType.RSA,
      {
        modulusLength: modulusLength * 1024,
        publicKeyEncoding: {
          type: publicKeyEncoding,
          format: "pem",
        },
        privateKeyEncoding: {
          type: privateKeyEncoding,
          format: "pem",
          cipher: "aes-256-cbc",
          passphrase,
        },
      },
      (err, publicKey, privateKey) => {
        if (err) reject(err);

        resolve({
          algorithms: [Algorithm.RS256, Algorithm.RS384, Algorithm.RS512],
          passphrase,
          privateKey,
          publicKey,
          type: KeyType.RSA,
        });
      },
    );
  });
};
