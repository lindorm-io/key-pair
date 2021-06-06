import { JWK } from "../types";
import { KeyPair } from "../entity";
import { filter, find, orderBy } from "lodash";
import { isKeyExpired, isKeyPrivate, isKeyUsable } from "../util";

interface Options {
  keys: Array<KeyPair>;
}

interface TTL {
  seconds: number;
  milliseconds: number;
}

export class Keystore {
  private readonly keys: Array<KeyPair>;

  public constructor(options: Options) {
    const keys = options.keys;

    if (!keys.length) {
      throw new Error("Keystore was initialised without keys");
    }

    this.keys = orderBy(keys, ["created", "expires"], ["desc", "asc"]);
  }

  public getJWKS(exposePrivateKeys = false): Array<JWK> {
    const keys: Array<JWK> = [];

    for (const keyPair of this.getKeys()) {
      keys.push(keyPair.toJWK(exposePrivateKeys));
    }

    return keys;
  }

  public getKey(id: string): KeyPair {
    const key = find(this.getKeys(), { id });

    if (!key) {
      throw new Error(`Key by id [ ${id} ] could not be found`);
    }

    return key;
  }

  public getKeys(): Array<KeyPair> {
    return filter(this.keys, isKeyUsable);
  }

  public getPrivateKeys(): Array<KeyPair> {
    return orderBy(filter(this.getKeys(), isKeyPrivate), ["external"], ["asc"]);
  }

  public getSigningKey(): KeyPair {
    const keys = this.getPrivateKeys();

    if (!keys.length) {
      throw new Error("Keys could not be found");
    }

    return keys[0];
  }

  public static getTTL(key: KeyPair): TTL | undefined {
    if (!key.expires) return undefined;
    if (isKeyExpired(key)) return undefined;

    const ttl = key.expires.getTime() - new Date().getTime();

    return {
      seconds: Math.round(ttl / 1000),
      milliseconds: ttl,
    };
  }
}
