import { ExtendableError } from "@lindorm-io/global";

export class KeyPairAssertError extends ExtendableError {
  constructor() {
    super("Invalid Certificate");
  }
}
