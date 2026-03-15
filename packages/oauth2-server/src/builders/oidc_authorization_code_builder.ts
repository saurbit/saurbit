import {
  AuthorizationCodeAccessTokenResult,
  AuthorizationCodeGrantContext,
  AuthorizationCodeReqData,
  AuthorizationCodeTokenRequest,
  GenerateAuthorizationCodeFunction,
  GetUserForAuthenticationFunction,
} from "../grants/authorization_code.ts";
import {
  OAuth2GenerateAccessTokenFromRefreshTokenFunction,
  OAuth2GenerateAccessTokenFunction,
  OAuth2GetClientFunction,
  OAuth2RefreshTokenRequest,
} from "../grants/flow.ts";
import {
  OIDCAuthorizationCodeAccessTokenResult,
  OIDCAuthorizationCodeEndpointContext,
  OIDCAuthorizationCodeEndpointRequest,
  OIDCAuthorizationCodeFlow,
  OIDCAuthorizationCodeFlowOptions,
  OIDCAuthorizationCodeModel,
} from "../oidc/oidc_authorization_code.ts";
import { OAuth2FlowBuilder } from "./flow_builder.ts";

export class OIDCAuthorizationCodeFlowBuilder<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
> extends OAuth2FlowBuilder {
  protected model: OIDCAuthorizationCodeModel<AuthReqData>;
  protected discoveryUrl: string;
  protected jwksEndpoint: string;
  protected openIdConfiguration?: Record<string, string | string[] | undefined>;
  protected authorizationEndpoint?: string;

  constructor(params: Partial<OIDCAuthorizationCodeFlowOptions<AuthReqData>>) {
    const {
      model,
      authorizationEndpoint,
      discoveryUrl,
      jwksEndpoint,
      openIdConfiguration,
      ...rest
    } = params;
    super(rest);
    this.model = model || {
      generateAccessToken() {
        return undefined;
      },
      generateAuthorizationCode() {
        return undefined;
      },
      getClient() {
        return undefined;
      },
      getClientForAuthentication() {
        return undefined;
      },
      getUserForAuthentication() {
        return undefined;
      },
    };
    this.discoveryUrl = discoveryUrl || "/.well-known/openid-configuration";
    this.jwksEndpoint = jwksEndpoint || "/.well-known/jwks.json";
    this.openIdConfiguration = openIdConfiguration;
    this.authorizationEndpoint = authorizationEndpoint;
  }

  setDiscoveryUrl(url: string): this {
    this.discoveryUrl = url;
    return this;
  }

  setJwksEndpoint(url: string): this {
    this.jwksEndpoint = url;
    return this;
  }

  setOpenIdConfiguration(config: Record<string, string | string[] | undefined>): this {
    this.openIdConfiguration = config;
    return this;
  }

  getDiscoveryUrl(): string {
    return this.discoveryUrl;
  }

  getJwksEndpoint(): string {
    return this.jwksEndpoint;
  }

  getOpenIdConfiguration(): Record<string, string | string[] | undefined> | undefined {
    return this.openIdConfiguration;
  }

  setAuthorizationEndpoint(url: string): this {
    this.authorizationEndpoint = url;
    return this;
  }

  getAuthorizationEndpoint(): string | undefined {
    return this.authorizationEndpoint;
  }

  generateAccessToken(
    handler: OAuth2GenerateAccessTokenFunction<
      AuthorizationCodeGrantContext,
      OIDCAuthorizationCodeAccessTokenResult
    >,
  ): this {
    this.model.generateAccessToken = handler;
    return this;
  }

  generateAccessTokenFromRefreshToken(
    handler: OAuth2GenerateAccessTokenFromRefreshTokenFunction<
      AuthorizationCodeAccessTokenResult
    >,
  ): this {
    this.model.generateAccessTokenFromRefreshToken = handler;
    return this;
  }

  generateAuthorizationCode(
    handler: GenerateAuthorizationCodeFunction<
      OIDCAuthorizationCodeEndpointContext
    >,
  ): this {
    this.model.generateAuthorizationCode = handler;
    return this;
  }

  getClient(
    handler: OAuth2GetClientFunction<AuthorizationCodeTokenRequest | OAuth2RefreshTokenRequest>,
  ): this {
    this.model.getClient = handler;
    return this;
  }

  getClientForAuthentication(
    handler: OAuth2GetClientFunction<OIDCAuthorizationCodeEndpointRequest>,
  ): this {
    this.model.getClientForAuthentication = handler;
    return this;
  }

  getUserForAuthentication(
    handler: GetUserForAuthenticationFunction<
      OIDCAuthorizationCodeEndpointContext,
      AuthReqData
    >,
  ): this {
    this.model.getUserForAuthentication = handler;
    return this;
  }

  protected override buildParams(): OIDCAuthorizationCodeFlowOptions<AuthReqData> {
    return {
      ...super.buildParams(),
      model: this.model,
      authorizationEndpoint: this.authorizationEndpoint,
      discoveryUrl: this.discoveryUrl,
      jwksEndpoint: this.jwksEndpoint,
      openIdConfiguration: this.openIdConfiguration,
    };
  }

  override build(): OIDCAuthorizationCodeFlow<AuthReqData> {
    return new OIDCAuthorizationCodeFlow<AuthReqData>(this.buildParams());
  }
}
