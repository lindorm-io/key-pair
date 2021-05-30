import MockDate from "mockdate";
import { KeyPair } from "./KeyPair";
import { Algorithm, KeyType, NamedCurve } from "../enum";

MockDate.set("2020-01-01T08:00:00.000Z");

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

describe("KeyPair.ts", () => {
  let keyPair: KeyPair;

  beforeEach(() => {
    keyPair = new KeyPair({
      id: "259ff47d-e334-4784-a478-04bf6d6b5d84",
      algorithms: [Algorithm.ES512, Algorithm.ES384, Algorithm.ES256],
      allowed: true,
      expires: new Date("2020-01-01T08:00:00.000Z"),
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
    expect(
      new KeyPair({
        id: "02dc19eb-2b8b-4a83-a0c0-9ac2b306bb9a",
        algorithms: [Algorithm.RS256, Algorithm.RS384],
        publicKey: "publicKey",
        type: KeyType.RSA,
      }),
    ).toMatchSnapshot();
  });

  test("should get/set allowed", () => {
    expect(keyPair.allowed).toBe(true);

    const allowed = false;
    keyPair.allowed = false;

    expect(keyPair.allowed).toBe(allowed);
    expect(keyPair.events).toMatchSnapshot();
  });

  test("should get/set expires", () => {
    expect(keyPair.expires).toStrictEqual(new Date("2020-01-01T08:00:00.000Z"));

    const expires = new Date("2021-01-01T00:00:01.000Z");
    keyPair.expires = expires;

    expect(keyPair.expires).toBe(expires);
    expect(keyPair.events).toMatchSnapshot();
  });

  test("should get/set preferredAlgorithm", () => {
    expect(keyPair.preferredAlgorithm).toBe(Algorithm.ES512);

    const preferredAlgorithm = Algorithm.ES384;
    keyPair.preferredAlgorithm = preferredAlgorithm;

    expect(keyPair.preferredAlgorithm).toBe(preferredAlgorithm);
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

  test("should convert to JWK", () => {
    expect(keyPair.toJWK(true)).toMatchSnapshot();
  });

  test("should create a new KeyPair from JWK", () => {
    expect(
      KeyPair.fromJWK({
        alg: "ES512",
        crv: "P-521",
        key_ops: [],
        kid: "391a4598-5dc6-4e3c-b1d9-a971ac55b3bb",
        kty: "EC",
        use: "sig",
        d: "AJk+YtHhPoobRdEZXzK9URIT7mB7dvGYeH6TmK8kP06Ha/lVRX8f/zD9vc9CRik+fb6XkcTMxktFNve1Xkq3HbMu",
        x: "AAsJtfdgSmaSxsm1swOSCodmSxeEwxQ1vcdkLVySpZAGLcGZYNIvJ9cUtQGQc9S3CDvjkR0bkrxq4HLYqC4Kwodz",
        y: "AJcSMpJWmZ97gv03gXIIbH57p01RN6CpVcUTXW+s4NxnQ6UDhuWKeyBdB7F14rXQZQKhvluoGpjvv6ON4bdk2wuW",
      }),
    ).toMatchSnapshot();
  });
});
