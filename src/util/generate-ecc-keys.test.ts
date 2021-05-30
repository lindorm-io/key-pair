import { generateECCKeys } from "./generate-ecc-keys";
import { NamedCurve } from "../enum";

describe("generateECCKeys", () => {
  test("should generate with default options", async () => {
    const result = await generateECCKeys();

    expect(result.publicKey).toContain("-----BEGIN PUBLIC KEY-----");
    expect(result.publicKey).toContain("-----END PUBLIC KEY-----");
    expect(result.publicKey.length).toBe(268);

    expect(result.privateKey).toContain("-----BEGIN EC PRIVATE KEY-----");
    expect(result.privateKey).toContain("-----END EC PRIVATE KEY-----");
    expect(result.privateKey.length).toBe(365);

    expect(result.type).toBe("ec");
  });

  test("should generate with namedCurve P-384", async () => {
    const result = await generateECCKeys({
      namedCurve: NamedCurve.P384,
    });

    expect(result.publicKey.length).toBe(215);
    expect(result.privateKey.length).toBe(288);
  });

  test("should generate with namedCurve P-256", async () => {
    const result = await generateECCKeys({
      namedCurve: NamedCurve.P256,
    });

    expect(result.publicKey.length).toBe(178);
    expect(result.privateKey.length).toBe(227);
  });

  test("should generate with privateKeyEncoding", async () => {
    const result = await generateECCKeys({
      privateKeyEncoding: "pkcs8",
    });

    expect(result.privateKey).toContain("-----BEGIN PRIVATE KEY-----");
    expect(result.privateKey).toContain("-----END PRIVATE KEY-----");
    expect(result.privateKey.length).toBe(384);
  });

  test("should generate with publicKeyEncoding", async () => {
    const result = await generateECCKeys({
      publicKeyEncoding: "spki",
    });

    expect(result.publicKey.length).toBe(268);
  });
});
