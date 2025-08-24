export interface SecureGenerateOptions {
  /**
   * The desired length of the password.
   *
   * @default 16
   */
  length?: number;
  /**
   * Include uppercase letters.
   *
   * @default true
   */
  uppercase?: boolean | string;
  /**
   * Include lowercase letters.
   *
   * @default true
   */
  lowercase?: boolean | string;
  /**
   * Include numbers.
   *
   * @default true
   */
  numbers?: boolean | string;
  /**
   * Include the default special characters.
   *
   * @default true
   */
  specials?: boolean | string;
}

/**
 * @deprecated Use `SecureGenerateOptions` instead.
 */
export type GeneratePasswordOptions = SecureGenerateOptions;
