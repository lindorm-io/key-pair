import { Asn1SequenceDecoder } from "./Asn1SequenceDecoder";
import { Asn1SequenceEncoder } from "./Asn1SequenceEncoder";
import { IJoseData, IJwkRSA } from "../../types";
import { createPrivateKey, createPublicKey } from "crypto";

export const encodeRSA = ({ privateKey, publicKey }: IJoseData): IJwkRSA => {
  if (!publicKey) {
    throw new Error(`Invalid publicKey [ ${publicKey} ]`);
  }

  if (!privateKey) {
    const key = createPublicKey({
      key: publicKey,
      format: "pem",
      type: "pkcs1",
    });
    const der = key.export({ format: "der", type: "pkcs1" });
    const dec = new Asn1SequenceDecoder(der);

    const n = dec.unsignedInteger().toString("base64");
    const e = dec.unsignedInteger().toString("base64");

    dec.end();

    return {
      n,
      e,
    };
  }

  if (privateKey) {
    const key = createPrivateKey({
      key: privateKey,
      format: "pem",
      type: "pkcs8",
      passphrase: "",
    });
    const der = key.export({ format: "der", type: "pkcs1" });
    const dec = new Asn1SequenceDecoder(der);

    dec.unsignedInteger();
    dec.unsignedInteger();
    dec.unsignedInteger();

    const d = dec.unsignedInteger().toString("base64");
    const p = dec.unsignedInteger().toString("base64");
    const q = dec.unsignedInteger().toString("base64");
    const dp = dec.unsignedInteger().toString("base64");
    const dq = dec.unsignedInteger().toString("base64");
    const qi = dec.unsignedInteger().toString("base64");

    dec.end();

    return {
      ...encodeRSA({ publicKey }),
      d,
      p,
      q,
      dp,
      dq,
      qi,
    };
  }

  throw new Error("publicKey is required");
};

export const decodeRSA = ({ d, dp, dq, e, n, p, q, qi }: IJwkRSA): IJoseData => {
  const isPrivate = d !== undefined;

  const enc = new Asn1SequenceEncoder();
  const modulus = Buffer.from(n, "base64");
  const exponent = Buffer.from(e, "base64");

  if (!isPrivate) {
    enc.unsignedInteger(modulus);
    enc.unsignedInteger(exponent);

    const der = enc.end();
    const key = createPublicKey({
      key: der,
      format: "der",
      type: "pkcs1",
    });
    const publicKey = key.export({ format: "pem", type: "pkcs1" }) as string;

    return { publicKey };
  }

  enc.zero();
  enc.unsignedInteger(modulus);
  enc.unsignedInteger(exponent);
  enc.unsignedInteger(Buffer.from(d!, "base64"));
  enc.unsignedInteger(Buffer.from(p!, "base64"));
  enc.unsignedInteger(Buffer.from(q!, "base64"));
  enc.unsignedInteger(Buffer.from(dp!, "base64"));
  enc.unsignedInteger(Buffer.from(dq!, "base64"));
  enc.unsignedInteger(Buffer.from(qi!, "base64"));

  const der = enc.end();
  const key = createPrivateKey({
    key: der,
    format: "der",
    type: "pkcs1",
  });
  const privateKey = key.export({ format: "pem", type: "pkcs1" }) as string;

  return {
    ...decodeRSA({ e, n }),
    privateKey,
  };
};
