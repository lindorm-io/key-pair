import Joi from "joi";
import { Algorithm, KeyPairEvent, KeyType, NamedCurve } from "../enum";
import {
  EntityBase,
  EntityCreationError,
  IEntityAttributes,
  IEntityOptions,
  JOI_ENTITY_BASE,
} from "@lindorm-io/entity";
import { JOI_KEY_ALGORITHMS, JOI_KEY_NAMED_CURVE, JOI_KEY_TYPE } from "../constant";

export interface IKeyPairAttributes extends IEntityAttributes {
  algorithms: Array<Algorithm>;
  allowed: boolean;
  expires: Date | null;
  namedCurve: NamedCurve | null;
  passphrase: string | null;
  privateKey: string | null;
  publicKey: string;
  type: KeyType;
}

export interface IKeyPairOptions extends IEntityOptions {
  algorithms: Array<Algorithm>;
  allowed?: boolean;
  expires?: Date;
  namedCurve?: NamedCurve;
  passphrase?: string;
  privateKey?: string;
  publicKey: string;
  type: KeyType;
}

const schema = Joi.object({
  ...JOI_ENTITY_BASE,

  algorithms: JOI_KEY_ALGORITHMS.required(),
  allowed: Joi.boolean().required(),
  expires: Joi.date().allow(null).required(),
  namedCurve: JOI_KEY_NAMED_CURVE.allow(null).required(),
  passphrase: Joi.string().allow(null).required(),
  privateKey: Joi.string().allow(null).required(),
  publicKey: Joi.string().required(),
  type: JOI_KEY_TYPE.required(),
});

export class KeyPair extends EntityBase<IKeyPairAttributes> {
  public readonly algorithms: Array<Algorithm>;
  public readonly namedCurve: NamedCurve | null;
  public readonly passphrase: string | null;
  public readonly privateKey: string | null;
  public readonly publicKey: string;
  public readonly type: KeyType;
  private _allowed: boolean;
  private _expires: Date | null;

  public constructor(options: IKeyPairOptions) {
    super(options);

    this._allowed = options.allowed !== false;
    this._expires = options.expires || null;

    this.algorithms = options.algorithms;
    this.namedCurve = options.namedCurve || null;
    this.passphrase = options.passphrase || null;
    this.privateKey = options.privateKey || null;
    this.publicKey = options.publicKey;
    this.type = options.type;
  }

  public get allowed(): boolean {
    return this._allowed;
  }
  public set allowed(allowed: boolean) {
    this._allowed = allowed;
    this.addEvent(KeyPairEvent.ALLOWED_CHANGED, { allowed: this._allowed });
  }

  public get expires(): Date | null {
    return this._expires;
  }
  public set expires(expires: Date | null) {
    this._expires = expires;
    this.addEvent(KeyPairEvent.EXPIRES_CHANGED, { expires: this._expires });
  }

  public create(): void {
    for (const evt of this.events) {
      if (evt.name !== KeyPairEvent.CREATED) continue;
      throw new EntityCreationError(this.constructor.name);
    }

    this.addEvent(KeyPairEvent.CREATED, this.toJSON());
  }

  public getKey(): string {
    return this.id;
  }

  public async schemaValidation(): Promise<void> {
    await schema.validateAsync(this.toJSON());
  }

  public toJSON(): IKeyPairAttributes {
    return {
      ...this.defaultJSON(),

      algorithms: this.algorithms,
      allowed: this.allowed,
      expires: this.expires,
      namedCurve: this.namedCurve,
      passphrase: this.passphrase,
      privateKey: this.privateKey,
      publicKey: this.publicKey,
      type: this.type,
    };
  }
}
