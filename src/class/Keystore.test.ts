import { Keystore } from "./Keystore";
import { KeyPair } from "../entity";

describe("Keystore.ts", () => {
  let key1: KeyPair;
  let key2: KeyPair;
  let key3: KeyPair;

  let getKeys: () => Array<KeyPair>;

  beforeEach(() => {
    key1 = new KeyPair({
      id: "mock-id-1",
      created: new Date("2020-01-01"),
      expired: null,
      algorithm: "RS512",
      type: "rsa",
      passphrase: "mock-passphrase-1",
      privateKey: "mock-private-key-1",
      publicKey: "mock-public-key-1",
    });
    key2 = new KeyPair({
      id: "mock-id-2",
      created: new Date("2020-02-02"),
      expired: null,
      algorithm: "ES512",
      type: "ec",
      privateKey: "mock-private-key-2",
      publicKey: "mock-public-key-2",
    });
    key3 = new KeyPair({
      id: "mock-id-3",
      created: new Date("2020-03-03"),
      expired: null,
      algorithm: "RS512",
      type: "rsa",
      passphrase: "mock-passphrase-3",
      privateKey: "mock-private-key-3",
      publicKey: "mock-public-key-3",
    });

    getKeys = () => [key1, key2, key3];
  });

  test("should return zero length", () => {
    const store = new Keystore({ keys: undefined });

    expect(store.getLength()).toBe(0);
  });

  test("should return the latest created key", () => {
    const store = new Keystore({ keys: getKeys() });

    expect(store.getCurrentKey().id).toBe("mock-id-3");
  });

  test("should return the latest active key", () => {
    key2 = new KeyPair({
      id: "mock-id-2",
      created: new Date("2020-02-02"),
      expired: new Date("2020-02-03"),
      algorithm: "ES512",
      type: "ec",
      privateKey: "mock-private-key-2",
      publicKey: "mock-public-key-2",
    });
    key3 = new KeyPair({
      id: "mock-id-3",
      created: new Date("2020-03-03"),
      expired: new Date("2020-02-03"),
      algorithm: "RS512",
      type: "rsa",
      passphrase: "mock-passphrase-3",
      privateKey: "mock-private-key-3",
      publicKey: "mock-public-key-3",
    });

    const store = new Keystore({ keys: getKeys() });

    expect(store.getCurrentKey().id).toBe("mock-id-1");
  });

  test("should return a specific key", () => {
    const store = new Keystore({ keys: getKeys() });

    expect(store.getKey("mock-id-2").id).toBe("mock-id-2");
  });

  test("should throw error if no active key can be found", () => {
    key1 = new KeyPair({
      id: "mock-id-1",
      created: new Date("2020-01-01"),
      expired: new Date("2020-02-03"),
      algorithm: "RS512",
      type: "rsa",
      passphrase: "mock-passphrase-1",
      privateKey: "mock-private-key-1",
      publicKey: "mock-public-key-1",
    });
    key2 = new KeyPair({
      id: "mock-id-2",
      created: new Date("2020-02-02"),
      expired: new Date("2020-02-03"),
      algorithm: "ES512",
      type: "ec",
      privateKey: "mock-private-key-2",
      publicKey: "mock-public-key-2",
    });
    key3 = new KeyPair({
      id: "mock-id-3",
      created: new Date("2020-03-03"),
      expired: new Date("2020-02-03"),
      algorithm: "RS512",
      type: "rsa",
      passphrase: "mock-passphrase-3",
      privateKey: "mock-private-key-3",
      publicKey: "mock-public-key-3",
    });

    const store = new Keystore({ keys: getKeys() });

    expect(() => store.getCurrentKey()).toThrowError(new Error("Key could not be found."));
  });
});
