import MockDate from "mockdate";
import { Keystore } from "./Keystore";
import { KeyPair } from "../entity";

MockDate.set("2020-01-02 08:00:00.000");

const d1 = new Date("2020-01-01 08:00:00.000");
const d2 = new Date("2020-01-01 09:00:00.000");
const d3 = new Date("2020-01-01 10:00:00.000");

const dateBefore = new Date("2020-01-02 02:00:00.000");
const dateAfter = new Date("2020-01-02 22:00:00.000");

describe("Keystore.ts", () => {
  let key1: KeyPair;
  let key2: KeyPair;
  let key3: KeyPair;

  let getKeys: () => Array<KeyPair>;

  beforeEach(() => {
    key1 = new KeyPair({
      id: "mock-id-1",
      created: d1,
      expires: null,
      algorithm: "RS512",
      type: "rsa",
      passphrase: "mock-passphrase-1",
      privateKey: "mock-private-key-1",
      publicKey: "mock-public-key-1",
    });
    key2 = new KeyPair({
      id: "mock-id-2",
      created: d2,
      expires: null,
      algorithm: "ES512",
      type: "ec",
      privateKey: "mock-private-key-2",
      publicKey: "mock-public-key-2",
    });
    key3 = new KeyPair({
      id: "mock-id-3",
      created: d3,
      expires: null,
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
      created: d2,
      expires: dateBefore,
      algorithm: "ES512",
      type: "ec",
      privateKey: "mock-private-key-2",
      publicKey: "mock-public-key-2",
    });
    key2 = new KeyPair({
      id: "mock-id-2",
      created: d2,
      expires: dateAfter,
      algorithm: "ES512",
      type: "ec",
      privateKey: "mock-private-key-2",
      publicKey: "mock-public-key-2",
    });
    key3 = new KeyPair({
      id: "mock-id-3",
      created: d3,
      expires: dateAfter,
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
      created: d1,
      expires: dateAfter,
      algorithm: "RS512",
      type: "rsa",
      passphrase: "mock-passphrase-1",
      privateKey: "mock-private-key-1",
      publicKey: "mock-public-key-1",
    });
    key2 = new KeyPair({
      id: "mock-id-2",
      created: d2,
      expires: dateAfter,
      algorithm: "ES512",
      type: "ec",
      privateKey: "mock-private-key-2",
      publicKey: "mock-public-key-2",
    });
    key3 = new KeyPair({
      id: "mock-id-3",
      created: d3,
      expires: dateAfter,
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
