import { IJwk } from "../types";
import { KeyPair } from "../entity";
import { filter, find, orderBy } from "lodash";
import { isAfter, isBefore } from "date-fns";

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

  public getUsableKeys(): Array<KeyPair> {
    return filter(this.keys, Keystore.isKeyUsable);
  }

  public getAllKeys(): Array<KeyPair> {
    return this.keys;
  }

  public getJWKS(exposePrivateKeys = false): Array<IJwk> {
    const keys: Array<IJwk> = [];

    for (const keyPair of this.getUsableKeys()) {
      keys.push(keyPair.toJWK(exposePrivateKeys));
    }

    return keys;
  }

  public getCurrentKey(): KeyPair {
    const keys = this.getUsableKeys();

    if (!keys.length) {
      throw new Error("Keys could not be found");
    }

    return keys[0];
  }

  public getKey(id: string): KeyPair {
    const key = find(this.getAllKeys(), { id });

    if (!key) {
      throw new Error(`Key by id [ ${id} ] could not be found`);
    }

    if (Keystore.isKeyExpired(key)) {
      throw new Error(`Key by id [ ${id} ] is expired`);
    }

    return key;
  }

  public static getTTL(key: KeyPair): TTL | undefined {
    if (Keystore.isKeyExpired(key)) return undefined;
    if (!key.expires) return undefined;

    const ttl = key.expires.getTime() - new Date().getTime();

    return {
      seconds: Math.round(ttl / 1000),
      milliseconds: ttl,
    };
  }

  public static isKeyUsable(key: KeyPair): boolean {
    if (!key.allowed) return false;
    if (key.expires === null) return true;

    return isBefore(new Date(), key.expires);
  }

  public static isKeyExpired(key: KeyPair): boolean {
    if (!key.allowed) return true;
    if (key.expires === null) return false;

    return isAfter(new Date(), key.expires);
  }
}
