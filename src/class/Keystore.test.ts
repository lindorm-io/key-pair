import MockDate from "mockdate";
import { Keystore } from "./Keystore";
import { KeyPair } from "../entity";

MockDate.set("2020-01-02 08:00:00.000");

const d1 = new Date("2020-01-01 08:00:00.000");
const d2 = new Date("2020-01-01 09:00:00.000");
const d3 = new Date("2020-01-01 10:00:00.000");
const d4 = new Date("2020-01-01 11:00:00.000");

const dateExpired = new Date("2020-01-02 02:00:00.000");
const dateExpiresTomorrow = new Date("2020-01-03 07:00:00.000");
const dateExpiresNextMonth = new Date("2020-02-02 08:00:00.000");

describe("Keystore.ts", () => {
  let key1: KeyPair;
  let key2: KeyPair;
  let key3: KeyPair;
  let key4: KeyPair;

  let keystore: Keystore;

  let getKeys: () => Array<KeyPair>;

  beforeEach(() => {
    key1 = new KeyPair({
      id: "mock-id-1",
      created: d1,
      expires: dateExpired,
      algorithm: "RS512",
      type: "rsa",
      passphrase: "mock-passphrase-1",
      privateKey: "mock-private-key-1",
      publicKey: "mock-public-key-1",
    });
    key2 = new KeyPair({
      id: "mock-id-2",
      created: d2,
      expires: dateExpiresTomorrow,
      algorithm: "ES512",
      type: "ec",
      privateKey: "mock-private-key-2",
      publicKey: "mock-public-key-2",
    });
    key3 = new KeyPair({
      id: "mock-id-3",
      created: d3,
      expires: dateExpiresNextMonth,
      algorithm: "RS512",
      type: "rsa",
      passphrase: "mock-passphrase-3",
      privateKey: "mock-private-key-3",
      publicKey: "mock-public-key-3",
    });
    key4 = new KeyPair({
      id: "mock-id-4",
      created: d4,
      expires: null,
      algorithm: "RS512",
      type: "rsa",
      passphrase: "mock-passphrase-4",
      privateKey: "mock-private-key-4",
      publicKey: "mock-public-key-4",
    });

    getKeys = () => [key1, key2, key3, key4];
    keystore = new Keystore({ keys: getKeys() });
  });

  test("should return all keys that can be used", () => {
    const keys = keystore.getUsableKeys();

    expect(keys.length).toBe(3);
    expect(keys[0].id).toBe("mock-id-4");
    expect(keys[1].id).toBe("mock-id-3");
    expect(keys[2].id).toBe("mock-id-2");
  });

  test("should return all keys", () => {
    const keys = keystore.getAllKeys();

    expect(keys.length).toBe(4);
    expect(keys[0].id).toBe("mock-id-4");
    expect(keys[1].id).toBe("mock-id-3");
    expect(keys[2].id).toBe("mock-id-2");
    expect(keys[3].id).toBe("mock-id-1");
  });

  test("should get the current key", () => {
    const key = keystore.getCurrentKey();

    expect(key.id).toBe("mock-id-4");
  });

  test("should get a specific key", () => {
    const key = keystore.getKey("mock-id-2");

    expect(key.id).toBe("mock-id-2");
  });

  test("should consider key to be usable", () => {
    expect(Keystore.isKeyUsable(key1)).not.toBe(true);
    expect(Keystore.isKeyUsable(key2)).toBe(true);
    expect(Keystore.isKeyUsable(key3)).toBe(true);
    expect(Keystore.isKeyUsable(key4)).toBe(true);
  });

  test("should return expired status of key", () => {
    expect(Keystore.isKeyExpired(key1)).toBe(true);
    expect(Keystore.isKeyExpired(key2)).not.toBe(true);
    expect(Keystore.isKeyExpired(key3)).not.toBe(true);
    expect(Keystore.isKeyExpired(key4)).not.toBe(true);
  });

  test("should tell if key is expired or will expire soon", () => {
    expect(Keystore.isKeyExpiredTomorrow(key1)).toBe(true);
    expect(Keystore.isKeyExpiredTomorrow(key2)).toBe(true);
    expect(Keystore.isKeyExpiredTomorrow(key3)).not.toBe(true);
    expect(Keystore.isKeyExpiredTomorrow(key4)).not.toBe(true);
  });

  test("should throw error when specific key cannot be found", () => {
    expect(() => keystore.getKey("wrong")).toThrow(
      expect.objectContaining({
        message: "Key by id [ wrong ] could not be found",
      }),
    );
  });

  test("should throw error when specific key is expired", () => {
    expect(() => keystore.getKey("mock-id-1")).toThrow(
      expect.objectContaining({
        message: "Key by id [ mock-id-1 ] is expired",
      }),
    );
  });
});
