import { ExtendableError, ExtendableErrorOptions } from "@lindorm-io/errors";

export class KeyPairError extends ExtendableError {
  public constructor(message: string, options?: ExtendableErrorOptions) {
    super(message, options);
  }
}
