import {
  ClientCredentialsFlow,
  ClientCredentialsFlowOptions,
  ClientCredentialsGrantContext,
  ClientCredentialsModel,
  ClientCredentialsTokenRequest,
} from "../grants/client_credentials.ts";
import {
  OAuth2AccessTokenResult,
  OAuth2GenerateAccessTokenFunction,
  OAuth2GetClientFunction,
} from "../grants/flow.ts";
import { OAuth2FlowBuilder } from "./flow_builder.ts";

export class ClientCredentialsFlowBuilder extends OAuth2FlowBuilder {
  protected model: ClientCredentialsModel;

  constructor(params: Partial<ClientCredentialsFlowOptions>) {
    const { model, ...rest } = params;
    super(rest);
    this.model = model || {
      generateAccessToken() {
        return undefined;
      },
      getClient() {
        return undefined;
      },
    };
  }

  override noneAuthenticationMethod(): this {
    return this;
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

  protected override buildParams(): ClientCredentialsFlowOptions {
    return {
      ...super.buildParams(),
      model: this.model,
    };
  }

  build(): ClientCredentialsFlow {
    return new ClientCredentialsFlow(
      this.buildParams(),
    );
  }
}
