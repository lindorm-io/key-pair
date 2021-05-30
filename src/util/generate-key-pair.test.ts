import { generateECCKeys as _generateECCKeys } from "./generate-ecc-keys";
import { generateRSAKeys as _generateRSAKeys } from "./generate-rsa-keys";
import { generateKeyPair } from "./generate-key-pair";
import { KeyType, NamedCurve } from "../enum";
import { KeyPair } from "../entity";

jest.mock("./generate-ecc-keys", () => ({
  generateECCKeys: jest.fn().mockResolvedValue({
    algorithms: ["algorithms"],
    privateKey: "ec-privateKey",
    publicKey: "ec-publicKey",
  }),
}));
jest.mock("./generate-rsa-keys", () => ({
  generateRSAKeys: jest.fn().mockResolvedValue({
    algorithms: ["algorithms"],
    privateKey: "rsa-privateKey",
    publicKey: "rsa-publicKey",
  }),
}));

const generateECCKeys = _generateECCKeys as jest.Mock;
const generateRSAKeys = _generateRSAKeys as jest.Mock;

describe("generateKeyPair", () => {
  afterEach(jest.clearAllMocks);

  test("should generate EC KeyPair", async () => {
    await expect(generateKeyPair({ type: KeyType.EC })).resolves.toStrictEqual(expect.any(KeyPair));

    expect(generateECCKeys).toHaveBeenCalled();
  });

  test("should generate EC KeyPair with namedCurve", async () => {
    await expect(generateKeyPair({ namedCurve: NamedCurve.P384, type: KeyType.EC })).resolves.toStrictEqual(
      expect.any(KeyPair),
    );

    expect(generateECCKeys).toHaveBeenCalledWith({ namedCurve: NamedCurve.P384 });
  });

  test("should generate RSA KeyPair", async () => {
    await expect(generateKeyPair({ type: KeyType.RSA })).resolves.toStrictEqual(expect.any(KeyPair));

    expect(generateRSAKeys).toHaveBeenCalled();
  });

  test("should generate RSA KeyPair with passphrase", async () => {
    await expect(generateKeyPair({ passphrase: "pass", type: KeyType.RSA })).resolves.toStrictEqual(
      expect.any(KeyPair),
    );

    expect(generateRSAKeys).toHaveBeenCalledWith({ passphrase: "pass" });
  });
});
