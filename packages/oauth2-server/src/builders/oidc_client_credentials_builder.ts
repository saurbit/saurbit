import {
  ClientCredentialsGrantContext,
  ClientCredentialsModel,
  ClientCredentialsTokenRequest,
} from "../grants/client_credentials.ts";
import {
  OAuth2AccessTokenResult,
  OAuth2GenerateAccessTokenFunction,
  OAuth2GetClientFunction,
} from "../grants/flow.ts";
import {
  OIDCClientCredentialsFlow,
  OIDCClientCredentialsFlowOptions,
} from "../oidc/oidc_client_credentials.ts";
import { OAuth2FlowBuilder } from "./flow_builder.ts";

export class OIDCClientCredentialsBuilder extends OAuth2FlowBuilder {
  protected model: ClientCredentialsModel;
  protected discoveryUrl: string;
  protected jwksEndpoint?: string;
  protected openIdConfiguration?: Record<string, string | string[] | undefined>;

  constructor(params: Partial<OIDCClientCredentialsFlowOptions>) {
    const { model, discoveryUrl, jwksEndpoint, openIdConfiguration, ...rest } = params;
    super(rest);
    this.model = model || {
      generateAccessToken() {
        return undefined;
      },
      getClient() {
        return undefined;
      },
    };
    this.discoveryUrl = discoveryUrl || "/.well-known/openid-configuration";
    this.jwksEndpoint = jwksEndpoint;
    this.openIdConfiguration = openIdConfiguration;
  }

  static create(): OIDCClientCredentialsBuilder {
    return new OIDCClientCredentialsBuilder({});
  }

  override noneAuthenticationMethod(): this {
    return this;
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

  getJwksEndpoint(): string | undefined {
    return this.jwksEndpoint;
  }

  getOpenIdConfiguration(): Record<string, string | string[] | undefined> | undefined {
    return this.openIdConfiguration;
  }

  getClient(handler: OAuth2GetClientFunction<ClientCredentialsTokenRequest>): this {
    this.model.getClient = handler;
    return this;
  }

  generateAccessToken(
    handler: OAuth2GenerateAccessTokenFunction<
      ClientCredentialsGrantContext,
      OAuth2AccessTokenResult | string
    >,
  ): this {
    this.model.generateAccessToken = handler;
    return this;
  }

  protected override buildParams(): OIDCClientCredentialsFlowOptions {
    return {
      ...super.buildParams(),
      model: this.model,
      discoveryUrl: this.discoveryUrl,
      jwksEndpoint: this.jwksEndpoint,
      openIdConfiguration: this.openIdConfiguration,
    };
  }

  build(): OIDCClientCredentialsFlow {
    return new OIDCClientCredentialsFlow(
      this.buildParams(),
    );
  }
}
