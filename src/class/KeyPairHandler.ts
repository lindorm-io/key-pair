import { Algorithm, SignKey, SignMethod } from "../enum";
import { KeyPairAssertError } from "../error";
import { createSign, createVerify, privateDecrypt, privateEncrypt, publicDecrypt, publicEncrypt } from "crypto";

const SHA_ALGORITHM = "sha512";
const ENCRYPT_FORMAT = "base64";
const DECRYPT_FORMAT = "utf8";

export interface IKeyPairHandler {
  algorithm: string;
  passphrase?: string;
  privateKey: string;
  publicKey: string;
}

export interface IKeyData {
  key: string;
  passphrase?: string;
}

export class KeyPairHandler {
  private algorithm: string;
  private passphrase: string;
  private privateKey: string;
  private publicKey: string;

  constructor(options: IKeyPairHandler) {
    this.algorithm = options.algorithm;
    this.passphrase = options.passphrase || "";
    this.privateKey = options.privateKey;
    this.publicKey = options.publicKey;
  }

  private key(type: SignKey): IKeyData {
    if (type === SignKey.PRIVATE && this.algorithm === Algorithm.RS512) {
      return { key: this.privateKey, passphrase: this.passphrase };
    }

    if (type === SignKey.PRIVATE && this.algorithm === Algorithm.ES512) {
      return { key: this.privateKey };
    }

    if (type === SignKey.PUBLIC) {
      return { key: this.publicKey };
    }

    throw new Error(`Unsupported KeyType/Algorithm combination: [ ${type}/${this.algorithm} ]`);
  }

  public sign(input: string): string {
    const createdSign = createSign(SHA_ALGORITHM);
    createdSign.write(input);
    createdSign.end();

    return createdSign.sign(this.key(SignKey.PRIVATE), ENCRYPT_FORMAT);
  }

  public verify(input: string, signature: string): boolean {
    const createdVerify = createVerify(SHA_ALGORITHM);
    createdVerify.write(input);
    createdVerify.end();

    return createdVerify.verify(this.key(SignKey.PUBLIC), signature, ENCRYPT_FORMAT);
  }

  public assert(input: string, signature: string): void {
    if (this.verify(input, signature)) {
      return;
    }

    throw new KeyPairAssertError();
  }

  public encrypt(method: SignMethod, input: string): string {
    if (this.algorithm !== Algorithm.RS512) {
      throw new Error(`Algorithm does not support encryption/decryption: ${this.algorithm}`);
    }

    const keyType = method === SignMethod.PRIVATE_SIGN ? SignKey.PRIVATE : SignKey.PUBLIC;
    const action = method === SignMethod.PRIVATE_SIGN ? privateEncrypt : publicEncrypt;

    const buffer = Buffer.from(input, DECRYPT_FORMAT);
    const encrypted = action(this.key(keyType), buffer);

    return encrypted.toString(ENCRYPT_FORMAT);
  }

  public decrypt(method: SignMethod, signature: string): string {
    if (this.algorithm !== Algorithm.RS512) {
      throw new Error(`Algorithm does not support encryption/decryption: ${this.algorithm}`);
    }

    const keyType = method === SignMethod.PRIVATE_SIGN ? SignKey.PUBLIC : SignKey.PRIVATE;
    const action = method === SignMethod.PRIVATE_SIGN ? publicDecrypt : privateDecrypt;

    const buffer = Buffer.from(signature, ENCRYPT_FORMAT);
    const decrypted = action(this.key(keyType), buffer);

    return decrypted.toString(DECRYPT_FORMAT);
  }
}
