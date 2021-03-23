import { ExtendableError } from "@lindorm-io/errors";

export class KeyPairAssertError extends ExtendableError {
  constructor() {
    super("Invalid Key Pair Certificate");
  }
}
