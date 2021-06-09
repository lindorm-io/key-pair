import { ExtendableError, ExtendableErrorOptions } from "@lindorm-io/errors";

export class KeystoreError extends ExtendableError {
  public constructor(message: string, options?: ExtendableErrorOptions) {
    super(message, options);
  }
}
