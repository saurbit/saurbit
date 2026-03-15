import {
  AuthorizationCodeAccessTokenResult,
  AuthorizationCodeEndpointContext,
  AuthorizationCodeEndpointRequest,
  AuthorizationCodeFlowOptions,
  AuthorizationCodeGrantContext,
  AuthorizationCodeModel,
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
import { OAuth2Flow } from "../mod.ts";
import { OAuth2FlowBuilder } from "./flow_builder.ts";

export class AuthorizationCodeFlowBuilder<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
> extends OAuth2FlowBuilder {
  protected model: AuthorizationCodeModel<AuthReqData>;
  protected authorizationEndpoint?: string;

  constructor(params: Partial<AuthorizationCodeFlowOptions<AuthReqData>>) {
    const { model, authorizationEndpoint, ...rest } = params;
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
    this.authorizationEndpoint = authorizationEndpoint;
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
      AuthorizationCodeAccessTokenResult | string
    >,
  ): this {
    this.model.generateAccessToken = handler;
    return this;
  }

  generateAccessTokenFromRefreshToken(
    handler: OAuth2GenerateAccessTokenFromRefreshTokenFunction<
      AuthorizationCodeAccessTokenResult | string
    >,
  ): this {
    this.model.generateAccessTokenFromRefreshToken = handler;
    return this;
  }

  generateAuthorizationCode(
    handler: GenerateAuthorizationCodeFunction<AuthorizationCodeEndpointContext>,
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
    handler: OAuth2GetClientFunction<AuthorizationCodeEndpointRequest>,
  ): this {
    this.model.getClientForAuthentication = handler;
    return this;
  }

  getUserForAuthentication(
    handler: GetUserForAuthenticationFunction<
      AuthorizationCodeEndpointContext,
      AuthReqData
    >,
  ): this {
    this.model.getUserForAuthentication = handler;
    return this;
  }

  protected override buildParams(): AuthorizationCodeFlowOptions<AuthReqData> {
    return {
      ...super.buildParams(),
      model: this.model,
      authorizationEndpoint: this.authorizationEndpoint,
    };
  }

  override build(): OAuth2Flow {
    throw new Error("Method not implemented.");
  }
}
