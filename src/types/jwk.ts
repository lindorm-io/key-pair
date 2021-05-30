import { KeyType, NamedCurve } from "../enum";

export interface IDefaultJwk {
  alg: string;
  created?: number;
  crv?: string;
  expires?: number;
  key_ops: Array<string>;
  kid: string;
  kty: string;
  use: string;
}

export interface IJwkEC {
  d?: string;
  x: string;
  y: string;
  crv: string;
}

export interface IJwkRSA {
  d?: string;
  dp?: string;
  dq?: string;
  e: string;
  n: string;
  p?: string;
  q?: string;
  qi?: string;
}

export type IKeyJwk = IJwkEC | IJwkRSA;
export type IJwk = IDefaultJwk & IKeyJwk;

export interface IJoseData {
  privateKey?: string;
  publicKey: string;
}

export interface IJoseEcData extends IJoseData {
  crv: string;
}

export interface IEncodeKeysOptions {
  exposePrivateKey: boolean;
  namedCurve?: NamedCurve | null;
  privateKey?: string | null;
  publicKey: string;
  type: KeyType;
}
