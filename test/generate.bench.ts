import { bench, describe } from "vitest";
import { secureGenerate } from "../src";

describe("bench token generation", () => {
  const shifty = new Shifty(true, 16);

  describe("16 characters", () => {
    bench("unsecure", () => {
      secureGenerate(16);
    });

    bench("@deepsource/shifty", () => {
      shifty.generate(16);
    });
  });

  describe("32 characters", () => {
    bench("unsecure", () => {
      secureGenerate(32);
    });

    bench("@deepsource/shifty", () => {
      shifty.generate(32);
    });
  });

  describe("64 characters", () => {
    bench("unsecure", () => {
      secureGenerate(64);
    });

    bench("@deepsource/shifty", () => {
      shifty.generate(64);
    });
  });

  describe("128 characters", () => {
    bench("unsecure", () => {
      secureGenerate(128);
    });

    bench("@deepsource/shifty", () => {
      shifty.generate(128);
    });
  });

  describe("256 characters", () => {
    bench("unsecure", () => {
      secureGenerate(256);
    });

    bench("@deepsource/shifty", () => {
      shifty.generate(256);
    });
  });

  describe("384 characters", () => {
    bench("unsecure", () => {
      secureGenerate(384);
    });

    bench("@deepsource/shifty", () => {
      shifty.generate(384);
    });
  });

  describe("512 characters", () => {
    bench("unsecure", () => {
      secureGenerate(512);
    });

    bench("@deepsource/shifty", () => {
      shifty.generate(512);
    });
  });
});

/**
 * FORK OF `@deepsource/shifty` implementation
 *
 * source: https://github.com/DeepSourceCorp/shifty/commit/066bc1ccc294703becb90f31a8e2c400ba05e76b
 * license: MIT https://github.com/DeepSourceCorp/shifty/blob/066bc1ccc294703becb90f31a8e2c400ba05e76b/LICENSE
 */

const DEFAULT_LENGTH = 16;

export default class Shifty {
  private hardenPassword: boolean;
  private randomBuffer: Uint8Array;
  private defaultLength: number;
  private mode: "W3C" | "MS" | "Failover";

  /**
   * Constructor function
   * @param {boolean} [harden = true] - this hardens the token using special chars
   * @param {number} [defaultLength=DEFAULT_LENGTH] - the default length of the secret string in case no value is passed to generate
   * @return {void}
   */
  constructor(harden = true, defaultLength = DEFAULT_LENGTH) {
    this.hardenPassword = harden;
    this.randomBuffer = new Uint8Array(0);
    this.defaultLength = defaultLength;
    if (globalThis.crypto) {
      this.mode = "W3C";
    } else {
      this.mode = "Failover";
      // skipcq: JS-0002
      console.warn(
        "SHIFTY: Using failover method for generating secret, this uses Math.random() and is not cryptographically safe",
      );
    }
  }

  /**
   * Ensure the given character belongs to a valid character

   * @param {string} char
   * @return {boolean}
   */
  private _validateCharacter(char: string): boolean {
    const specials = [..."!@#$%^&*()_+{}:\"<>?|[];',./`~"];
    const lowercase = [..."abcdefghijklmnopqrstuvwxyz"];
    const uppercase = [..."ABCDEFGHIJKLMNOPQRSTUVWXYZ"];
    const numbers = [..."0123456789"];

    return [
      ...(this.hardenPassword ? specials : []),
      ...lowercase,
      ...uppercase,
      ...numbers,
    ].includes(char);
  }

  /**
   * Exposed generate function
   * @param {number} length
   * @return {string}
   */
  generate(length?: number): string {
    // eslint-disable-next-line unicorn/prefer-logical-operator-over-ternary
    length = length ? length : this.defaultLength;

    let secret = "";

    // The while loop ensures we always satisfy the length condition
    // If the inner loop ends before we have the token of the required length
    // the while loop will restart the inner loop
    while (secret.length < length) {
      // generate a new buffer everytime to ensure we don't end up with repeating values
      this.populateBuffer();

      for (
        let rollIndex = 0;
        rollIndex < this.randomBuffer.length;
        rollIndex++
      ) {
        // Generate character from the number
        // eslint-disable-next-line unicorn/prefer-code-point
        const char = String.fromCharCode(this.randomBuffer[rollIndex]!);
        if (this._validateCharacter(char)) {
          // Append the charcater to secret if it is valid
          secret += char;
        }

        if (secret.length === length) {
          break;
        }
      }
    }
    return secret;
  }

  /**
   * Populate the buffer using web crypto or failover
   * @return {void}
   */
  private populateBuffer(): void {
    // Generate a Unit8Array, this has all possible ASCII characters
    this.randomBuffer =
      this.mode === "W3C"
        ? this._useCryptoRandomBuffer()
        : this._useFailoverRandomBuffer();
  }

  /**
   * Generate a Uint8 Array using web crypto API
   *
   * @return {Uint8Array}
   */
  private _useCryptoRandomBuffer(): Uint8Array {
    const seed = new Uint8Array(256);

    // The Crypto.getRandomBuffer() method lets you get cryptographically strong random values.
    // The array given as the parameter is filled with random numbers (random in its cryptographic meaning).
    return globalThis.crypto.getRandomValues(seed);
  }

  /**
   * Generate a Uint8 Array using failsafe.
   * This is not cryptographically safe
   *
   * @return {Uint8Array}
   */
  private _useFailoverRandomBuffer(): Uint8Array {
    // not cryptographically safe
    const buffer = new Uint8Array(256);

    let randomNumberForCharacterGeneration = 0;
    for (let loopIndex = 0; loopIndex < buffer.length; loopIndex++) {
      // eslint-disable-next-line no-constant-condition
      while (1) {
        randomNumberForCharacterGeneration = Math.round(Math.random() * 256);
        if (
          randomNumberForCharacterGeneration >= 0 &&
          randomNumberForCharacterGeneration <= 255
        )
          break;
      }
      buffer[loopIndex] = randomNumberForCharacterGeneration;
    }

    return buffer;
  }
}
