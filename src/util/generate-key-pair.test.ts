import { generateEcKeys as _generateEcKeys } from "./generate-ec-keys";
import { generateRsaKeys as _generateRsaKeys } from "./generate-rsa-keys";
import { generateKeyPair } from "./generate-key-pair";
import { KeyType, NamedCurve } from "../enum";
import { KeyPair } from "../entity";

jest.mock("./generate-ec-keys", () => ({
  generateEcKeys: jest.fn().mockResolvedValue({
    algorithms: ["algorithms"],
    privateKey: "ec-privateKey",
    publicKey: "ec-publicKey",
  }),
}));
jest.mock("./generate-rsa-keys", () => ({
  generateRsaKeys: jest.fn().mockResolvedValue({
    algorithms: ["algorithms"],
    privateKey: "rsa-privateKey",
    publicKey: "rsa-publicKey",
  }),
}));

const generateEcKeys = _generateEcKeys as jest.Mock;
const generateRsaKeys = _generateRsaKeys as jest.Mock;

describe("generateKeyPair", () => {
  afterEach(jest.clearAllMocks);

  test("should generate EC KeyPair", async () => {
    await expect(generateKeyPair({ type: KeyType.EC })).resolves.toStrictEqual(expect.any(KeyPair));

    expect(generateEcKeys).toHaveBeenCalled();
  });

  test("should generate EC KeyPair with namedCurve", async () => {
    await expect(generateKeyPair({ namedCurve: NamedCurve.P384, type: KeyType.EC })).resolves.toStrictEqual(
      expect.any(KeyPair),
    );

    expect(generateEcKeys).toHaveBeenCalledWith({ namedCurve: NamedCurve.P384 });
  });

  test("should generate RSA KeyPair", async () => {
    await expect(generateKeyPair({ type: KeyType.RSA })).resolves.toStrictEqual(expect.any(KeyPair));

    expect(generateRsaKeys).toHaveBeenCalled();
  });

  test("should generate RSA KeyPair with passphrase", async () => {
    await expect(generateKeyPair({ passphrase: "pass", type: KeyType.RSA })).resolves.toStrictEqual(
      expect.any(KeyPair),
    );

    expect(generateRsaKeys).toHaveBeenCalledWith({ passphrase: "pass" });
  });
});
