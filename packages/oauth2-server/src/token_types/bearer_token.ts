import type { TokenType, TokenTypeValidationResponse } from "./types.ts";

export type BearerTokenValidation = (
  request: Request,
  token: string
) => TokenTypeValidationResponse | Promise<TokenTypeValidationResponse>;

export class BearerTokenType implements TokenType {
  readonly prefix = "Bearer" as const;
  #handler: BearerTokenValidation;

  constructor() {
    this.#handler = (_, token) => ({ isValid: !!token });
  }

  validate(handler: BearerTokenValidation): this {
    this.#handler = handler;
    return this;
  }

  isValid(request: Request, token: string): Promise<TokenTypeValidationResponse> | TokenTypeValidationResponse {
    return this.#handler(request, token);
  }
}