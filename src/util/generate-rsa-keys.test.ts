import { generateRSAKeys } from "./generate-rsa-keys";

describe("generate-rsa-keys.ts", () => {
  test("should generate a private/public key pair", async () => {
    const result = await generateRSAKeys();

    expect(result.algorithm).toBe("RS512");

    expect(result.passphrase.length).toBe(64);

    expect(result.publicKey).toContain("-----BEGIN RSA PUBLIC KEY-----");
    expect(result.publicKey).toContain("-----END RSA PUBLIC KEY-----");
    expect(result.publicKey.length).toBe(775);

    expect(result.privateKey).toContain("-----BEGIN RSA PRIVATE KEY-----");
    expect(result.privateKey).toContain("-----END RSA PRIVATE KEY-----");
    expect(result.privateKey.length).toBe(3326);

    expect(result.type).toBe("rsa");
  });
});
