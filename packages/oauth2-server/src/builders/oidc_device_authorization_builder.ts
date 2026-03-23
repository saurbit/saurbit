import {
  DeviceAuthorizationAccessTokenError,
  DeviceAuthorizationAccessTokenResult,
  DeviceAuthorizationEndpointContext,
  DeviceAuthorizationEndpointRequest,
  DeviceAuthorizationGrantContext,
  DeviceAuthorizationTokenRequest,
  GenerateDeviceCodeFunction,
} from "../grants/device_authorization.ts";
import {
  OAuth2GenerateAccessTokenFromRefreshTokenFunction,
  OAuth2GenerateAccessTokenFunction,
  OAuth2GetClientFunction,
  OAuth2RefreshTokenRequest,
} from "../grants/flow.ts";
import {
  OIDCDeviceAuthorizationAccessTokenResult,
  OIDCDeviceAuthorizationFlow,
  OIDCDeviceAuthorizationFlowOptions,
  OIDCDeviceAuthorizationModel,
} from "../oidc/oidc_device_authorization.ts";
import { OAuth2Client } from "../types.ts";
import { OAuth2FlowBuilder } from "./flow_builder.ts";

export class OIDCDeviceAuthorizationFlowBuilder extends OAuth2FlowBuilder {
  protected model: OIDCDeviceAuthorizationModel;
  protected discoveryUrl: string;
  protected jwksEndpoint: string;
  protected openIdConfiguration?: Record<string, string | string[] | undefined>;
  protected userInfoEndpoint?: string;
  protected registrationEndpoint?: string;
  protected authorizationEndpoint?: string;
  protected verificationEndpoint?: string;

  constructor(params: Partial<OIDCDeviceAuthorizationFlowOptions>) {
    const {
      model,
      authorizationEndpoint,
      verificationEndpoint,
      discoveryUrl,
      jwksEndpoint,
      openIdConfiguration,
      userInfoEndpoint,
      registrationEndpoint,
      ...rest
    } = params;
    super(rest);
    this.model = model || {
      generateAccessToken() {
        return undefined;
      },
      generateDeviceCode() {
        return undefined;
      },
      getClient() {
        return undefined;
      },
      getClientForAuthentication() {
        return undefined;
      },
      verifyUserCode() {
        return undefined;
      },
    };
    this.discoveryUrl = discoveryUrl || "/.well-known/openid-configuration";
    this.jwksEndpoint = jwksEndpoint || "/.well-known/jwks.json";
    this.openIdConfiguration = openIdConfiguration;
    this.userInfoEndpoint = userInfoEndpoint;
    this.registrationEndpoint = registrationEndpoint;
    this.authorizationEndpoint = authorizationEndpoint;
    this.verificationEndpoint = verificationEndpoint;
  }

  setAuthorizationEndpoint(url: string): this {
    this.authorizationEndpoint = url;
    return this;
  }

  getAuthorizationEndpoint(): string | undefined {
    return this.authorizationEndpoint;
  }

  setVerificationEndpoint(url: string): this {
    this.verificationEndpoint = url;
    return this;
  }

  getVerificationEndpoint(): string | undefined {
    return this.verificationEndpoint;
  }

  generateAccessToken(
    handler: OAuth2GenerateAccessTokenFunction<
      DeviceAuthorizationGrantContext,
      OIDCDeviceAuthorizationAccessTokenResult | DeviceAuthorizationAccessTokenError
    >,
  ): this {
    this.model.generateAccessToken = handler;
    return this;
  }

  generateAccessTokenFromRefreshToken(
    handler: OAuth2GenerateAccessTokenFromRefreshTokenFunction<
      DeviceAuthorizationAccessTokenResult
    >,
  ): this {
    this.model.generateAccessTokenFromRefreshToken = handler;
    return this;
  }

  generateDeviceCode(
    handler: GenerateDeviceCodeFunction<DeviceAuthorizationEndpointContext>,
  ): this {
    this.model.generateDeviceCode = handler;
    return this;
  }

  getClient(
    handler: OAuth2GetClientFunction<DeviceAuthorizationTokenRequest | OAuth2RefreshTokenRequest>,
  ): this {
    this.model.getClient = handler;
    return this;
  }

  getClientForAuthentication(
    handler: OAuth2GetClientFunction<DeviceAuthorizationEndpointRequest>,
  ): this {
    this.model.getClientForAuthentication = handler;
    return this;
  }

  verifyUserCode(
    handler: (userCode: string) =>
      | Promise<
        | { deviceCode: string; client: OAuth2Client }
        | undefined
      >
      | { deviceCode: string; client: OAuth2Client }
      | undefined,
  ): this {
    this.model.verifyUserCode = handler;
    return this;
  }

  protected override buildParams(): OIDCDeviceAuthorizationFlowOptions {
    return {
      ...super.buildParams(),
      model: this.model,
      discoveryUrl: this.discoveryUrl,
      jwksEndpoint: this.jwksEndpoint,
      userInfoEndpoint: this.userInfoEndpoint,
      registrationEndpoint: this.registrationEndpoint,
      openIdConfiguration: this.openIdConfiguration,
      authorizationEndpoint: this.authorizationEndpoint,
      verificationEndpoint: this.verificationEndpoint,
    };
  }

  override build(): OIDCDeviceAuthorizationFlow {
    return new OIDCDeviceAuthorizationFlow(this.buildParams());
  }
}
