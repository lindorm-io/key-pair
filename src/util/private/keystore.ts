import { KeyPair } from "../../entity";
import { isAfter, isBefore } from "date-fns";
import { isString } from "lodash";

export const isKeyExpired = (key: KeyPair): boolean => {
  if (key.expires === null) return false;

  return isAfter(new Date(), key.expires);
};

export const isKeyPrivate = (key: KeyPair): boolean => {
  return isString(key.privateKey);
};

export const isKeyUsable = (key: KeyPair): boolean => {
  if (!key.allowed) return false;
  if (key.expires === null) return true;

  return isBefore(new Date(), key.expires);
};
