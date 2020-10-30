import { filter, find, orderBy } from "lodash";
import { KeyPair } from "../entity";

export interface IKeystoreOptions {
  keys: Array<KeyPair>;
}

export class Keystore {
  private keys: Array<KeyPair>;

  constructor(options: IKeystoreOptions) {
    const filtered = filter(options.keys, (key: KeyPair) => !key.expired);
    this.keys = orderBy(filtered, ["created"], ["desc"]);
  }

  public getCurrentKey(): KeyPair {
    if (!this.keys.length) {
      throw new Error("Key could not be found.");
    }

    return this.keys[0];
  }

  public getKey(id: string): KeyPair {
    const key = find(this.keys, { id });

    if (!key) {
      throw new Error(`Key by id [ ${id} ] could not be found.`);
    }

    return key;
  }
}
