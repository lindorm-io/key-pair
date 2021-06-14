import Joi from "joi";
import { Algorithm, KeyPairEvent, KeyType, NamedCurve } from "../enum";
import { JOI_KEY_ALGORITHM, JOI_KEY_ALGORITHMS, JOI_KEY_NAMED_CURVE, JOI_KEY_TYPE } from "../constant";
import { JoseData, JWK, KeyJWK } from "../types";
import { KeyPairError } from "../error";
import { camelKeys, snakeKeys } from "@lindorm-io/core";
import { decodeKeys, encodeKeys } from "../util";
import { includes, isString, orderBy } from "lodash";
import {
  EntityAttributes,
  EntityCreationError,
  EntityOptions,
  JOI_ENTITY_BASE,
  LindormEntity,
} from "@lindorm-io/entity";

export interface KeyPairAttributes extends EntityAttributes {
  algorithms: Array<Algorithm>;
  allowed: Date;
  expires: Date | null;
  external: boolean;
  namedCurve: NamedCurve | null;
  passphrase: string | null;
  preferredAlgorithm: Algorithm;
  privateKey: string | null;
  publicKey: string;
  type: KeyType;
}

export interface KeyPairOptions extends EntityOptions {
  algorithms: Array<Algorithm>;
  allowed?: Date;
  expires?: Date | null;
  external?: boolean;
  namedCurve?: NamedCurve | null;
  passphrase?: string | null;
  preferredAlgorithm?: Algorithm;
  privateKey?: string | null;
  publicKey: string;
  type: KeyType;
}

const schema = Joi.object({
  ...JOI_ENTITY_BASE,

  algorithms: JOI_KEY_ALGORITHMS.required(),
  allowed: Joi.date().required(),
  expires: Joi.date().allow(null).required(),
  external: Joi.boolean().required(),
  namedCurve: JOI_KEY_NAMED_CURVE.allow(null).required(),
  passphrase: Joi.string().allow(null).required(),
  preferredAlgorithm: JOI_KEY_ALGORITHM.required(),
  privateKey: Joi.string().allow(null).required(),
  publicKey: Joi.string().required(),
  type: JOI_KEY_TYPE.required(),
});

export class KeyPair extends LindormEntity<KeyPairAttributes> {
  public readonly algorithms: Array<Algorithm>;
  public readonly external: boolean;
  public readonly namedCurve: NamedCurve | null;
  public readonly passphrase: string | null;
  public readonly privateKey: string | null;
  public readonly publicKey: string;
  public readonly type: KeyType;
  private _allowed: Date;
  private _expires: Date | null;
  private _preferredAlgorithm: Algorithm;

  public constructor(options: KeyPairOptions) {
    super(options);

    this._allowed = options.allowed || this.created;
    this._expires = options.expires || null;
    this._preferredAlgorithm =
      options.preferredAlgorithm || orderBy(options.algorithms, [(item): Algorithm => item], ["desc"])[0];

    this.algorithms = options.algorithms;
    this.external = options.external === true;
    this.namedCurve = options.namedCurve || null;
    this.passphrase = options.passphrase || null;
    this.privateKey = options.privateKey || null;
    this.publicKey = options.publicKey;
    this.type = options.type;
  }

  public get allowed(): Date {
    return this._allowed;
  }
  public set allowed(allowed: Date) {
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
      throw new KeyPairError("Invalid preferredAlgorithm", {
        data: { preferredAlgorithm },
        debug: {
          algorithms: this.algorithms,
        },
      });
    }

    this._preferredAlgorithm = preferredAlgorithm;
    this.addEvent(KeyPairEvent.PREFERRED_ALGORITHM_CHANGED, { preferredAlgorithm: this._preferredAlgorithm });
  }

  public create(): void {
    for (const evt of this.events) {
      if (evt.name !== KeyPairEvent.CREATED) continue;
      throw new EntityCreationError(this.constructor.name);
    }

    const { events, ...rest } = this.toJSON();
    this.addEvent(KeyPairEvent.CREATED, rest);
  }

  public getKey(): string {
    return this.id;
  }

  public async schemaValidation(): Promise<void> {
    await schema.validateAsync(this.toJSON());
  }

  public toJSON(): KeyPairAttributes {
    return {
      ...this.defaultJSON(),

      algorithms: this.algorithms,
      allowed: this.allowed,
      expires: this.expires,
      external: this.external,
      namedCurve: this.namedCurve,
      passphrase: this.passphrase,
      preferredAlgorithm: this.preferredAlgorithm,
      privateKey: this.privateKey,
      publicKey: this.publicKey,
      type: this.type,
    };
  }

  public toJWK(exposePrivateKey = false): JWK {
    const data: KeyJWK = encodeKeys({
      exposePrivateKey,
      namedCurve: this.namedCurve,
      privateKey: this.privateKey,
      publicKey: this.publicKey,
      type: this.type,
    });

    const keyOps = ["verify"];

    if (isString(this.privateKey)) {
      keyOps.push("sign");

      if (this.type === KeyType.RSA && (this.passphrase?.length || 0) < 1) {
        keyOps.push("encrypt");
      }
    }
    if (this.type === KeyType.RSA) {
      keyOps.push("decrypt");
    }

    return snakeKeys({
      alg: this.preferredAlgorithm,
      allowedFrom: this.allowed.getTime(),
      createdAt: this.created.getTime(),
      crv: this.namedCurve ? this.namedCurve : undefined,
      expiresAt: this.expires ? this.expires.getTime() : undefined,
      keyOps: keyOps.sort(),
      kid: this.id,
      kty: this.type,
      use: "sig",
      ...data,
    });
  }

  public static fromJWK(jwk: JWK): KeyPair {
    const data: JoseData = decodeKeys(jwk);
    const camel = camelKeys(jwk);

    return new KeyPair({
      id: camel.kid,
      algorithms: [camel.alg as Algorithm],
      allowed: camel.allowedFrom ? new Date(camel.allowedFrom) : undefined,
      created: camel.createdAt ? new Date(camel.createdAt) : undefined,
      expires: camel.expiresAt ? new Date(camel.expiresAt) : undefined,
      external: true,
      namedCurve: camel.crv ? (camel.crv as NamedCurve) : undefined,
      preferredAlgorithm: camel.alg as Algorithm,
      type: camel.kty as KeyType,
      ...data,
    });
  }
}
