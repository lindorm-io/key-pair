import { Algorithm, KeyType, NamedCurve } from "../enum";
import { KeyPair } from "../entity";
import { generateEcKeys } from "./generate-ec-keys";
import { generateRsaKeys } from "./generate-rsa-keys";

interface IOptions {
  namedCurve?: NamedCurve;
  passphrase?: string;
  type: KeyType;
}

export const generateKeyPair = async (options: IOptions): Promise<KeyPair> => {
  const { namedCurve, passphrase, type } = options;

  let algorithms: Array<Algorithm>;
  let privateKey: string;
  let publicKey: string;

  switch (type) {
    case KeyType.EC:
      ({ algorithms, privateKey, publicKey } = await generateEcKeys({ namedCurve }));
      break;

    case KeyType.RSA:
      ({ algorithms, privateKey, publicKey } = await generateRsaKeys({ passphrase }));
      break;

    default:
      throw new Error("Invalid type");
  }

  return new KeyPair({
    algorithms,
    privateKey,
    publicKey,
    type,
  });
};
