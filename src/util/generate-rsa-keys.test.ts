import { generateRSAKeys } from "./generate-rsa-keys";

describe("generateRSAKeys", () => {
  test("should generate with default options", async () => {
    const result = await generateRSAKeys();

    expect(result.publicKey).toContain("-----BEGIN PUBLIC KEY-----");
    expect(result.publicKey).toContain("-----END PUBLIC KEY-----");
    expect(result.publicKey.length).toBe(800);

    expect(result.privateKey).toContain("-----BEGIN ENCRYPTED PRIVATE KEY-----");
    expect(result.privateKey).toContain("-----END ENCRYPTED PRIVATE KEY-----");
    expect(result.privateKey.length).toBe(3434);

    expect(result.type).toBe("rsa");
  });

  test("should generate with modulusLength 1", async () => {
    const result = await generateRSAKeys({ modulusLength: 1 });

    expect(result.publicKey.length).toBe(272);
    expect(result.privateKey.length).toBe(1074);
  });

  test("should generate with modulusLength 2", async () => {
    const result = await generateRSAKeys({ modulusLength: 2 });

    expect(result.publicKey.length).toBe(451);
    expect(result.privateKey.length).toBe(1874);
  });

  test("should generate with modulusLength 3", async () => {
    const result = await generateRSAKeys({ modulusLength: 3 });

    expect(result.publicKey.length).toBe(625);
    expect(result.privateKey.length).toBe(2654);
  });

  test("should generate with passphrase", async () => {
    const result = await generateRSAKeys({ passphrase: "passphrase" });

    expect(result.publicKey.length).toBe(800);
    expect(result.privateKey.length).toBe(3434);
  });

  test("should generate with privateKeyEncoding", async () => {
    const result = await generateRSAKeys({ privateKeyEncoding: "pkcs1" });

    expect(result.privateKey.length).toBe(3326);
  });

  test("should generate with publicKeyEncoding", async () => {
    const result = await generateRSAKeys({ publicKeyEncoding: "pkcs1" });

    expect(result.publicKey.length).toBe(775);
  });
});
