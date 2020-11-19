import MockDate from "mockdate";
import { KeyPair } from "./KeyPair";

jest.mock("uuid", () => ({
  v4: jest.fn(() => "mock-uuid"),
}));

MockDate.set("2020-01-01 08:00:00.000");
const date = new Date("2020-01-01 08:00:00.000");

describe("KeyPair.ts", () => {
  let keyPair: KeyPair;

  beforeEach(() => {
    keyPair = new KeyPair({
      algorithm: "algorithm",
      expires: date,
      passphrase: "passphrase",
      privateKey: "privateKey",
      publicKey: "publicKey",
      type: "type",
    });
  });

  test("should have all data", () => {
    expect(keyPair).toMatchSnapshot();
  });

  test("should have optional data", () => {
    keyPair = new KeyPair({
      algorithm: "algorithm",
      type: "type",
    });

    expect(keyPair).toMatchSnapshot();
  });

  test("should create", () => {
    keyPair.create();
    expect(keyPair.events).toMatchSnapshot();
  });

  test("should get algorithm", () => {
    expect(keyPair.algorithm).toBe("algorithm");
  });

  test("should get/set expires", () => {
    expect(keyPair.expires).toBe(date);

    const expires = new Date("2021-01-01 00:00:01");
    keyPair.expires = expires;

    expect(keyPair.expires).toBe(expires);
    expect(keyPair.events).toMatchSnapshot();
  });

  test("should get passphrase", () => {
    expect(keyPair.passphrase).toBe("passphrase");
  });

  test("should get privateKey", () => {
    expect(keyPair.privateKey).toBe("privateKey");
  });

  test("should get publicKey", () => {
    expect(keyPair.publicKey).toBe("publicKey");
  });

  test("should get type", () => {
    expect(keyPair.type).toBe("type");
  });
});
