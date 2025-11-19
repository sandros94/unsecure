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
   * Include special characters.
   *
   * @default true
   */
  specials?: boolean | string;
  /**
   * Include a timestamp at the beginning of the string.
   *
   * @default false
   */
  timestamp?: true | Date;
}

/**
 * @deprecated Use `SecureGenerateOptions` instead.
 */
export type GeneratePasswordOptions = SecureGenerateOptions;
