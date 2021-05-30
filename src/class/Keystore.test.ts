import MockDate from "mockdate";
import { Keystore } from "./Keystore";
import { KeyPair } from "../entity";
import { Algorithm, KeyType, NamedCurve } from "../enum";

MockDate.set("2020-01-02T08:00:00.000Z");

jest.mock("../util", () => ({
  decodeKeys: () => ({
    privateKey: "privateKey",
    publicKey: "publicKey",
  }),
  encodeKeys: () => ({
    crv: "crv",
    d: "d",
    dp: "dp",
    dq: "dq",
    e: "e",
    n: "n",
    p: "p",
    q: "q",
    qi: "qi",
    x: "x",
    y: "y",
  }),
}));

describe("Keystore.ts", () => {
  const key1 = new KeyPair({
    id: "8cf5c1eb-f51d-404e-8b1b-14e5f84018ce",
    algorithms: [Algorithm.RS512],
    allowed: true,
    created: new Date("2020-01-01T08:00:00.000Z"),
    expires: new Date("2020-01-02T02:00:00.000Z"),
    passphrase: "mock-passphrase-1",
    privateKey: "mock-private-key-1",
    publicKey: "mock-public-key-1",
    type: KeyType.RSA,
  });
  const key2 = new KeyPair({
    id: "73b5f592-15db-40a1-8b09-ce835dc2afae",
    algorithms: [Algorithm.ES512],
    allowed: true,
    created: new Date("2020-01-01T09:00:00.000Z"),
    expires: new Date("2020-01-03T07:00:00.000Z"),
    namedCurve: NamedCurve.P521,
    privateKey: "mock-private-key-2",
    publicKey: "mock-public-key-2",
    type: KeyType.EC,
  });
  const key3 = new KeyPair({
    id: "dd4ba4a2-6578-4249-8be1-415fb548c001",
    algorithms: [Algorithm.RS512],
    allowed: true,
    created: new Date("2020-01-01T10:00:00.000Z"),
    expires: new Date("2020-02-02T08:00:00.000Z"),
    passphrase: "mock-passphrase-3",
    privateKey: "mock-private-key-3",
    publicKey: "mock-public-key-3",
    type: KeyType.RSA,
  });
  const key4 = new KeyPair({
    id: "04114c01-0685-43ce-b7a1-99721486c1f7",
    algorithms: [Algorithm.RS512],
    allowed: true,
    created: new Date("2020-01-01T11:00:00.000Z"),
    passphrase: "mock-passphrase-4",
    privateKey: "mock-private-key-4",
    publicKey: "mock-public-key-4",
    type: KeyType.RSA,
  });
  const key5 = new KeyPair({
    id: "051616e4-3478-4bfc-99e9-4cf7c312a2c6",
    algorithms: [Algorithm.RS512],
    allowed: false,
    created: new Date("2020-01-01T12:00:00.000Z"),
    passphrase: "mock-passphrase-5",
    privateKey: "mock-private-key-5",
    publicKey: "mock-public-key-5",
    type: KeyType.RSA,
  });

  const keystore = new Keystore({ keys: [key1, key2, key3, key4, key5] });

  test("should return all keys that can be used", () => {
    expect(keystore.getUsableKeys()).toStrictEqual([key4, key3, key2]);
  });

  test("should return all keys", () => {
    expect(keystore.getAllKeys()).toStrictEqual([key5, key4, key3, key2, key1]);
  });

  test("should return keys as jwks", () => {
    expect(keystore.getJWKS(true)).toMatchSnapshot();
  });

  test("should return the current key", () => {
    expect(keystore.getCurrentKey()).toStrictEqual(key4);
  });

  test("should return a specific key", () => {
    expect(keystore.getKey("73b5f592-15db-40a1-8b09-ce835dc2afae")).toStrictEqual(key2);
  });

  test("should return usable status of key", () => {
    expect(Keystore.isKeyUsable(key1)).toBe(false);
    expect(Keystore.isKeyUsable(key2)).toBe(true);
    expect(Keystore.isKeyUsable(key3)).toBe(true);
    expect(Keystore.isKeyUsable(key4)).toBe(true);
    expect(Keystore.isKeyUsable(key5)).toBe(false);
  });

  test("should return expired status of key", () => {
    expect(Keystore.isKeyExpired(key1)).toBe(true);
    expect(Keystore.isKeyExpired(key2)).toBe(false);
    expect(Keystore.isKeyExpired(key3)).toBe(false);
    expect(Keystore.isKeyExpired(key4)).toBe(false);
    expect(Keystore.isKeyExpired(key5)).toBe(true);
  });

  test("should throw when specific key cannot be found", () => {
    expect(() => keystore.getKey("wrong")).toThrow(Error);
  });

  test("should throw when specific key is expired", () => {
    expect(() => keystore.getKey(key1.id)).toThrow(Error);
  });

  test("should throw when specific key is disallowed", () => {
    expect(() => keystore.getKey(key5.id)).toThrow(Error);
  });
});
