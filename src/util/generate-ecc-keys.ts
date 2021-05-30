import { Algorithm, KeyType, NamedCurve } from "../enum";
import { generateKeyPair } from "crypto";

interface IOptions {
  namedCurve?: NamedCurve;
  privateKeyEncoding?: "sec1" | "pkcs8";
  publicKeyEncoding?: "pkcs1" | "spki";
}

export interface IGenerateECCKeysData {
  algorithms: Array<Algorithm>;
  namedCurve: NamedCurve;
  privateKey: string;
  publicKey: string;
  type: KeyType;
}

export const generateECCKeys = async (options: IOptions = {}): Promise<IGenerateECCKeysData> => {
  const { namedCurve = NamedCurve.P521, publicKeyEncoding = "spki", privateKeyEncoding = "sec1" } = options;

  return new Promise((resolve, reject) => {
    generateKeyPair(
      KeyType.EC,
      {
        namedCurve,
        publicKeyEncoding: {
          type: publicKeyEncoding,
          format: "pem",
        },
        privateKeyEncoding: {
          type: privateKeyEncoding,
          format: "pem",
        },
      },
      (err, publicKey, privateKey) => {
        if (err) {
          reject(err);
        }
        resolve({
          algorithms: [Algorithm.ES256, Algorithm.ES384, Algorithm.ES512],
          namedCurve,
          privateKey,
          publicKey,
          type: KeyType.EC,
        });
      },
    );
  });
};
