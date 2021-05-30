import { IJoseData, IJwk, IJwkEC, IJwkRSA } from "../../types";
import { KeyType } from "../../enum";
import { decodeEC } from "./ec";
import { decodeRSA } from "./rsa";

export const decodeKeys = (jwk: IJwk): IJoseData => {
  switch (jwk.kty) {
    case KeyType.EC:
      return decodeEC(jwk as IJwkEC);

    case KeyType.RSA:
      return decodeRSA(jwk as IJwkRSA);

    default:
      throw new Error("Invalid KeyType");
  }
};
