import { EntityBase, IEntity, IEntityBaseOptions, EntityCreationError } from "@lindorm-io/common";
import { KeyPairEvent } from "../enum";

export interface IKeyPair extends IEntity {
  algorithm: string;
  expired: Date;
  passphrase: string;
  privateKey: string;
  publicKey: string;
  type: string;
}

export interface IKeyPairOptions extends IEntityBaseOptions {
  algorithm: string;
  expired?: Date;
  passphrase?: string;
  privateKey?: string;
  publicKey?: string;
  type: string;
}

export class KeyPair extends EntityBase implements IKeyPair {
  readonly algorithm: string;
  readonly passphrase: string;
  readonly privateKey: string;
  readonly publicKey: string;
  readonly type: string;
  private _expired: Date;

  constructor(options: IKeyPairOptions) {
    super(options);

    this.algorithm = options.algorithm;
    this.passphrase = options.passphrase || null;
    this.privateKey = options.privateKey || null;
    this.publicKey = options.publicKey || null;
    this.type = options.type;
    this._expired = options.expired || null;
  }

  public get expired(): Date {
    return this._expired;
  }

  public create(): void {
    for (const evt of this._events) {
      if (evt.name !== KeyPairEvent.CREATED) continue;
      throw new EntityCreationError(this.constructor.name);
    }

    this.addEvent(KeyPairEvent.CREATED, {
      algorithm: this.algorithm,
      passphrase: this.passphrase,
      privateKey: this.privateKey,
      publicKey: this.publicKey,
      type: this.type,
      expired: this._expired,
    });
  }

  public expire(): void {
    this._expired = new Date();
    this.addEvent(KeyPairEvent.EXPIRED, { expired: this._expired });
  }
}
