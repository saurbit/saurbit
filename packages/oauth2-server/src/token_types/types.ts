export type TokenTypeValidationResponse = {
  isValid?: boolean;
  message?: string;
  [key: string]: unknown;
};

export interface TokenType {
  readonly prefix: string;
  isValid: (request: Request, token: string) => TokenTypeValidationResponse | Promise<TokenTypeValidationResponse>;
  isValidTokenRequest?: (request: Request) => TokenTypeValidationResponse | Promise<TokenTypeValidationResponse>;
}