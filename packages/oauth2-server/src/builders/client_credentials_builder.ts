import { ClientSecretBasic } from "../client_auth_methods/client_secret_basic.ts";
import { ClientSecretPost } from "../client_auth_methods/client_secret_post.ts";
import { NoneAuthMethod } from "../client_auth_methods/none.ts";
import { ClientAuthMethod } from "../client_auth_methods/types.ts";
import {
  ClientCredentialsFlow,
  ClientCredentialsFlowOptions,
  ClientCredentialsGrantContext,
  ClientCredentialsTokenRequest,
} from "../grants/client_credentials.ts";
import {
  OAuth2AccessTokenResult,
  OAuth2GenerateAccessTokenFunction,
  OAuth2GetClientFunction,
} from "../grants/flow.ts";
import { StrategyVerifyTokenFunction } from "../strategy.ts";
import { TokenType } from "../token_types/types.ts";

export class ClientCredentialsBuilder {
  protected params: ClientCredentialsFlowOptions;
  protected description?: string | undefined;
  protected scopes: Record<string, string> = {};
  protected tokenType?: TokenType | undefined;
  protected clientAuthenticationMethods: Map<string, ClientAuthMethod> = new Map();

  constructor(params: Partial<ClientCredentialsFlowOptions>) {
    this.params = {
      strategyOptions: params.strategyOptions || {},
      model: params.model || {
        generateAccessToken() {
          return undefined;
        },
        getClient() {
          return undefined;
        },
      },
      ...params,
    };
  }

  static create(): ClientCredentialsBuilder {
    return new ClientCredentialsBuilder({});
  }

  getAccessTokenLifetime(): number | undefined {
    return this.params.accessTokenLifetime;
  }

  getSecuritySchemeName(): string | undefined {
    return this.params.securitySchemeName;
  }

  getTokenUrl(): string | undefined {
    return this.params.tokenUrl;
  }

  getDescription(): string | undefined {
    return this.description;
  }

  getScopes(): Record<string, string> {
    return { ...this.scopes };
  }

  setAccessTokenLifetime(lifetime: number): this {
    this.params.accessTokenLifetime = lifetime;
    return this;
  }

  setSecuritySchemeName(name: string): this {
    this.params.securitySchemeName = name;
    return this;
  }

  setTokenUrl(url: string): this {
    this.params.tokenUrl = url;
    return this;
  }

  setTokenType(tokenType: TokenType): this {
    this.tokenType = tokenType;
    return this;
  }

  setDescription(description: string): this {
    this.description = description;
    return this;
  }

  setScopes(scopes: Record<string, string>): this {
    this.scopes = scopes;
    return this;
  }

  getClient(handler: OAuth2GetClientFunction<ClientCredentialsTokenRequest>): this {
    this.params.model.getClient = handler;
    return this;
  }

  generateAccessToken(
    handler: OAuth2GenerateAccessTokenFunction<
      ClientCredentialsGrantContext,
      OAuth2AccessTokenResult | string
    >,
  ): this {
    this.params.model.generateAccessToken = handler;
    return this;
  }

  verifyToken(handler: StrategyVerifyTokenFunction<Request>): this {
    this.params.strategyOptions.verifyToken = handler;
    return this;
  }

  addClientAuthenticationMethod(
    clientAuthenticationMethod: ClientAuthMethod,
  ): this {
    this.clientAuthenticationMethods.set(
      clientAuthenticationMethod.method,
      clientAuthenticationMethod,
    );
    return this;
  }

  clientSecretBasicAuthenticationMethod(): this {
    const clientAuthenticationMethod = new ClientSecretBasic();
    this.clientAuthenticationMethods.set(
      clientAuthenticationMethod.method,
      clientAuthenticationMethod,
    );
    return this;
  }

  clientSecretPostAuthenticationMethod(): this {
    const clientAuthenticationMethod = new ClientSecretPost();
    this.clientAuthenticationMethods.set(
      clientAuthenticationMethod.method,
      clientAuthenticationMethod,
    );
    return this;
  }

  noneAuthenticationMethod(): this {
    const clientAuthenticationMethod = new NoneAuthMethod();
    this.clientAuthenticationMethods.set(
      clientAuthenticationMethod.method,
      clientAuthenticationMethod,
    );
    return this;
  }

  build(): ClientCredentialsFlow {
    const result = new ClientCredentialsFlow(this.params);
    if (this.tokenType) {
      result.setTokenType(this.tokenType);
    }
    if (this.scopes) {
      result.setScopes(this.scopes);
    }
    if (this.description) {
      result.setDescription(this.description);
    }
    for (const clientAuthenticationMethod of this.clientAuthenticationMethods.values()) {
      result.addClientAuthenticationMethod(clientAuthenticationMethod);
    }
    return result;
  }
}
