import { EntityBase, IEntity, IEntityBaseOptions, EntityCreationError } from "@lindorm-io/core";
import { KeyPairEvent } from "../enum";

export interface IKeyPair extends IEntity {
  algorithm: string;
  allowed: boolean;
  expires: Date;
  passphrase: string;
  privateKey: string;
  publicKey: string;
  type: string;
}

export interface IKeyPairOptions extends IEntityBaseOptions {
  algorithm: string;
  allowed?: boolean;
  expires?: Date;
  passphrase?: string;
  privateKey?: string;
  publicKey?: string;
  type: string;
}

export class KeyPair extends EntityBase implements IKeyPair {
  private _algorithm: string;
  private _allowed: boolean;
  private _expires: Date;
  private _passphrase: string;
  private _privateKey: string;
  private _publicKey: string;
  private _type: string;

  constructor(options: IKeyPairOptions) {
    super(options);

    this._algorithm = options.algorithm;
    this._allowed = options.allowed !== false;
    this._expires = options.expires || null;
    this._passphrase = options.passphrase || null;
    this._privateKey = options.privateKey || null;
    this._publicKey = options.publicKey || null;
    this._type = options.type;
  }

  public get algorithm(): string {
    return this._algorithm;
  }

  public get allowed(): boolean {
    return this._allowed;
  }
  public set allowed(allowed: boolean) {
    this._allowed = allowed;
    this.addEvent(KeyPairEvent.ALLOWED_CHANGED, { allowed: this._allowed });
  }

  public get expires(): Date {
    return this._expires;
  }
  public set expires(expires: Date) {
    this._expires = expires;
    this.addEvent(KeyPairEvent.EXPIRES_CHANGED, { expires: this._expires });
  }

  public get passphrase(): string {
    return this._passphrase;
  }

  public get privateKey(): string {
    return this._privateKey;
  }

  public get publicKey(): string {
    return this._publicKey;
  }

  public get type(): string {
    return this._type;
  }

  public create(): void {
    for (const evt of this._events) {
      if (evt.name !== KeyPairEvent.CREATED) continue;
      throw new EntityCreationError(this.constructor.name);
    }

    this.addEvent(KeyPairEvent.CREATED, {
      algorithm: this._algorithm,
      allowed: this._allowed,
      expires: this._expires,
      passphrase: this._passphrase,
      privateKey: this._privateKey,
      publicKey: this._publicKey,
      type: this._type,
    });
  }
}
