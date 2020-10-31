import { ExtendableError } from "@lindorm-io/core";

export class KeyPairAssertError extends ExtendableError {
  constructor() {
    super("Invalid Key Pair Certificate");
  }
}
