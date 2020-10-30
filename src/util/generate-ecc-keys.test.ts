import { generateECCKeys } from "./generate-ecc-keys";

describe("generate-ecc-keys.ts", () => {
  test("should generate a private/public key pair", async () => {
    const result = await generateECCKeys();

    expect(result.algorithm).toBe("ES512");

    expect(result.publicKey).toContain("-----BEGIN PUBLIC KEY-----");
    expect(result.publicKey).toContain("-----END PUBLIC KEY-----");
    expect(result.publicKey.length).toBe(268);

    expect(result.privateKey).toContain("-----END PRIVATE KEY-----");
    expect(result.privateKey).toContain("-----END PRIVATE KEY-----");
    expect(result.privateKey.length).toBe(384);

    expect(result.type).toBe("ec");
  });
});
