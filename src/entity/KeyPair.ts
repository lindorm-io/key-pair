import Joi from "joi";
import { Algorithm, KeyPairEvent, KeyType, NamedCurve } from "../enum";
import { IJoseData, IJwk, IKeyJwk } from "../types";
import { JOI_KEY_ALGORITHM, JOI_KEY_ALGORITHMS, JOI_KEY_NAMED_CURVE, JOI_KEY_TYPE } from "../constant";
import { decodeKeys, encodeKeys } from "../util";
import { includes, orderBy } from "lodash";
import {
  EntityBase,
  EntityCreationError,
  IEntity,
  IEntityAttributes,
  IEntityOptions,
  JOI_ENTITY_BASE,
} from "@lindorm-io/entity";

export interface IKeyPairAttributes extends IEntityAttributes {
  algorithms: Array<Algorithm>;
  allowed: boolean;
  expires: Date | null;
  namedCurve: NamedCurve | null;
  passphrase: string | null;
  preferredAlgorithm: Algorithm;
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
  preferredAlgorithm?: Algorithm;
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
  preferredAlgorithm: JOI_KEY_ALGORITHM.required(),
  privateKey: Joi.string().allow(null).required(),
  publicKey: Joi.string().required(),
  type: JOI_KEY_TYPE.required(),
});

export class KeyPair extends EntityBase<IKeyPairAttributes> implements IEntity<IKeyPairAttributes> {
  public readonly algorithms: Array<Algorithm>;
  public readonly namedCurve: NamedCurve | null;
  public readonly passphrase: string | null;
  public readonly privateKey: string | null;
  public readonly publicKey: string;
  public readonly type: KeyType;
  private _allowed: boolean;
  private _expires: Date | null;
  private _preferredAlgorithm: Algorithm;

  public constructor(options: IKeyPairOptions) {
    super(options);

    this._allowed = options.allowed !== false;
    this._expires = options.expires || null;
    this._preferredAlgorithm = options.preferredAlgorithm || orderBy(options.algorithms, [(item) => item], ["desc"])[0];

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

  public get preferredAlgorithm(): Algorithm {
    return this._preferredAlgorithm;
  }
  public set preferredAlgorithm(preferredAlgorithm: Algorithm) {
    if (!includes(this.algorithms, preferredAlgorithm)) {
      throw new Error("Invalid preferredAlgorithm");
    }

    this._preferredAlgorithm = preferredAlgorithm;
    this.addEvent(KeyPairEvent.PREFERRED_ALGORITHM_CHANGED, { preferredAlgorithm: this._preferredAlgorithm });
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
      preferredAlgorithm: this.preferredAlgorithm,
      privateKey: this.privateKey,
      publicKey: this.publicKey,
      type: this.type,
    };
  }

  public toJWK(exposePrivateKey = false): IJwk {
    const data: IKeyJwk = encodeKeys({
      exposePrivateKey,
      namedCurve: this.namedCurve,
      privateKey: this.privateKey,
      publicKey: this.publicKey,
      type: this.type,
    });

    return {
      alg: this.preferredAlgorithm,
      created: this.created.getTime(),
      crv: this.namedCurve ? this.namedCurve : undefined,
      expires: this.expires ? this.expires.getTime() : undefined,
      key_ops: ["sign", "verify"],
      kid: this.id,
      kty: this.type,
      use: "sig",
      ...data,
    };
  }

  public static fromJWK(jwk: IJwk): KeyPair {
    const data: IJoseData = decodeKeys(jwk);

    return new KeyPair({
      id: jwk.kid,
      algorithms: [jwk.alg as Algorithm],
      created: jwk.created ? new Date(jwk.created) : undefined,
      expires: jwk.expires ? new Date(jwk.expires) : undefined,
      namedCurve: jwk.crv ? (jwk.crv as NamedCurve) : undefined,
      preferredAlgorithm: jwk.alg as Algorithm,
      type: jwk.kty as KeyType,
      ...data,
    });
  }
}
