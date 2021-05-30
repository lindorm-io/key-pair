import MockDate from "mockdate";
import { KeyPair } from "./KeyPair";
import { Algorithm, KeyType, NamedCurve } from "../enum";

MockDate.set("2020-01-01 08:00:00.000");
const date = new Date("2020-01-01 08:00:00.000");

describe("KeyPair.ts", () => {
  let keyPair: KeyPair;

  beforeEach(() => {
    keyPair = new KeyPair({
      id: "259ff47d-e334-4784-a478-04bf6d6b5d84",
      algorithms: [Algorithm.ES512],
      allowed: true,
      expires: date,
      namedCurve: NamedCurve.P521,
      passphrase: "",
      privateKey: "privateKey",
      publicKey: "publicKey",
      type: KeyType.EC,
    });
  });

  test("should have all data", () => {
    expect(keyPair).toMatchSnapshot();
  });

  test("should have optional data", () => {
    keyPair = new KeyPair({
      id: "02dc19eb-2b8b-4a83-a0c0-9ac2b306bb9a",
      algorithms: [Algorithm.RS256],
      publicKey: "publicKey",
      type: KeyType.RSA,
    });

    expect(keyPair).toMatchSnapshot();
  });

  test("should get/set allowed", () => {
    expect(keyPair.allowed).toBe(true);

    const allowed = false;
    keyPair.allowed = false;

    expect(keyPair.allowed).toBe(allowed);
    expect(keyPair.events).toMatchSnapshot();
  });

  test("should get/set expires", () => {
    expect(keyPair.expires).toBe(date);

    const expires = new Date("2021-01-01 00:00:01");
    keyPair.expires = expires;

    expect(keyPair.expires).toBe(expires);
    expect(keyPair.events).toMatchSnapshot();
  });

  test("should create", () => {
    keyPair.create();
    expect(keyPair.events).toMatchSnapshot();
  });

  test("should get key", () => {
    expect(keyPair.getKey()).toBe("259ff47d-e334-4784-a478-04bf6d6b5d84");
  });

  test("should validate schema", async () => {
    await expect(keyPair.schemaValidation()).resolves.toBeUndefined();
  });

  test("should get json", () => {
    expect(keyPair.toJSON()).toMatchSnapshot();
  });
});
