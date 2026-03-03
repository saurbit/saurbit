import { InvalidRequestError, OAuth2Error } from "../errors.ts";
import { BearerTokenType } from "../token_types/bearer_token.ts";
import { TokenType } from "../token_types/types.ts";
import { 
    ClientAuthMethod, 
    ClientSecretBasic, 
    ClientSecretPost, 
    NoneAuthMethod, 
    sortTokenEndpointAuthMethods, 
    TokenEndpointAuthMethod 
} from "../client_auth_methods/mod.ts";
import { JwtAuthority } from "../utils/jwt_authority.ts";
import { OAuth2TokenResponseBody } from "../types.ts";

export type OAuth2AuthFlowTokenResponse =
    | { success: true; data: OAuth2TokenResponseBody }
    | { success: false; error: OAuth2Error };

export interface OAuth2AuthFlowOptions {
    /*
    logger?: ILogger;
    jwksOptions?: OAuth2JwksOptions;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    jwksRoute?: IJWKSRoute<any>;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    options?: OAuth2AuthOptions<any>;
    */
    securitySchemeName?: string;
    accessTokenLifetime?: number;
}

export abstract class OAuth2AuthFlow {
    abstract readonly grantType: string;

    protected _clientAuthMethods: Record<TokenEndpointAuthMethod, ClientAuthMethod | undefined> = {
        client_secret_basic: undefined,
        client_secret_post: undefined,
        client_secret_jwt: undefined,
        private_key_jwt: undefined,
        none: undefined,
    };

    protected _tokenType: TokenType;

    get tokenType(): string {
        return this._tokenType.prefix;
    }

    protected get clientAuthMethods(): Record<TokenEndpointAuthMethod, ClientAuthMethod | undefined> {
        const result: Record<TokenEndpointAuthMethod, ClientAuthMethod | undefined> = {
            client_secret_basic: undefined,
            client_secret_post: undefined,
            client_secret_jwt: undefined,
            private_key_jwt: undefined,
            none: undefined,
        };

        const keys = Object.keys(this._clientAuthMethods)
            .map((key) => {
                const k = key as TokenEndpointAuthMethod;
                result[k] = this._clientAuthMethods[k];
                return this._clientAuthMethods[k] ? key : undefined;
            })
            .filter((key): key is TokenEndpointAuthMethod => !!key);

        if (!keys.length) {
            result.client_secret_basic = new ClientSecretBasic();
        }

        return result;
    }

    //
    protected securitySchemeName: string;
    protected description?: string;
    protected scopes?: Record<string, string>;
    
    /** Default lifetime (in seconds) for access tokens. @default {3600} */
    protected accessTokenLifetime: number = 3600;

    protected jwksPublicKeyTtl?: number;
    protected jwksRotationIntervalMs?: number;
    protected jwtAuthority?: JwtAuthority;
    /*
    protected options: OAuth2AuthOptions;
    
    protected logger?: ILogger;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    protected jwksRoute?: IJWKSRoute<any>;
    protected jwksKeyStore?: JwksKeyStore;
    
    protected jwksRotationTimestampStore?: JwksRotationTimestampStore;
    
    protected jwksRotator?: JwksRotator;
    */

    constructor(options?: OAuth2AuthFlowOptions) {
        this._tokenType = new BearerTokenType();
        this.securitySchemeName = options?.securitySchemeName || 'oauth2-auth-flow';
        this.accessTokenLifetime = options?.accessTokenLifetime || 3600;
        //this.options = options?.options ? { ...options.options } : {};

        //
        //this.jwksRoute = options?.jwksRoute;
        //this.jwksKeyStore = options?.jwksOptions?.keyStore;
        
        //this.jwksPublicKeyTtl = options?.jwksOptions?.ttl;
        //this.jwksRotationIntervalMs = options?.jwksOptions?.rotation?.intervalMs;
        
        //this.jwksRotationTimestampStore = options?.jwksOptions?.rotation?.timestampStore;
    }

    protected async extractClientCredentials(
        req: Request,
        authMethodsInstances: Record<TokenEndpointAuthMethod, ClientAuthMethod | undefined>,
        supported: TokenEndpointAuthMethod[]
    ): Promise<{
        clientId?: string;
        clientSecret?: string;
        error?: OAuth2Error;
    }> {
        let clientId: string | undefined;
        let clientSecret: string | undefined;
        let error: OAuth2Error | undefined;

        for (const am of supported) {
            const amInstance = authMethodsInstances[am];
            if (amInstance) {
                //console.log('Check', amInstance.method, '...')
                const v = await amInstance.extractClientCredentials(req as unknown as Request);
                if (v.hasAuthMethod) {
                    //console.log(amInstance.method, 'IS BEING USED')
                    clientId = v.clientId;
                    clientSecret = v.clientSecret;
                    if (!v.clientId) {
                        error = new InvalidRequestError(`${amInstance.method} authentication requires client_id`);
                    } else if (!amInstance.secretIsOptional && !v.clientSecret) {
                        error = new InvalidRequestError(`${amInstance.method} authentication requires client_secret`);
                    }
                    break;
                } else {
                    // console.log(amInstance.method, 'was not used')
                }
            }
        }

        return {
            error,
            clientId,
            clientSecret,
        };
    }

    /*
    protected getJwtAuthority(): JwtAuthority | undefined {
        if (this.jwtAuthority) return this.jwtAuthority;
        if (this.jwksRoute || this.jwksKeyStore || this.options.useAccessTokenJwks) {
            this.jwtAuthority = new JwtAuthority(this.jwksKeyStore || new InMemoryKeyStore(), this.jwksPublicKeyTtl);
        }
        return this.jwtAuthority;
    }

    async generateKeyPair(): Promise<void> {
        return await this.getJwtAuthority()?.generateKeyPair();
    }
    */

    /*
    protected getJwksRotator(): JwksRotator | undefined {
        if (this.jwksRotator) return this.jwksRotator;
        const jwtAuthority = this.getJwtAuthority();
        if (jwtAuthority && this.jwksRotationIntervalMs) {
            this.jwksRotator = new JwksRotator({
                keyGenerator: jwtAuthority,
                rotationIntervalMs: this.jwksRotationIntervalMs,
                rotatorKeyStore: this.jwksRotationTimestampStore || new InMemoryKeyStore(),
                logger: this.logger,
            });
        }
        return this.jwksRotator;
    }
    */

    /*
    protected createJwksEndpoint(t: KaapiTools) {
        const jwtAuthority = this.getJwtAuthority();

        if (this.jwksRoute && jwtAuthority) {
            t.route({
                path: this.jwksRoute.path,
                method: 'GET',
                options: {
                    plugins: {
                        kaapi: {
                            docs: false,
                        },
                    },
                },
                handler: async (req, h) => {
                    const jwks = await jwtAuthority.getJwksEndpointResponse();

                    if (this.jwksRoute?.handler) {
                        return this.jwksRoute.handler(
                            {
                                jwks,
                            },
                            req,
                            h
                        );
                    }

                    return jwks;
                },
            });
        }
    }
    */

    /*
    async checkAndRotateKeys(): Promise<void> {
        return this.getJwksRotator()?.checkAndRotateKeys();
    }
        */


    setTokenType(value: TokenType): this {
        this._tokenType = value;
        return this;
    }

    getTokenEndpointAuthMethods(): TokenEndpointAuthMethod[] {
        const result = Object.keys(this._clientAuthMethods)
            .map((key) => {
                return this._clientAuthMethods[key as TokenEndpointAuthMethod] ? key : undefined;
            })
            .filter((key): key is TokenEndpointAuthMethod => !!key);

        if (!result.length) {
            result.push('client_secret_basic');
        }

        return sortTokenEndpointAuthMethods(result);
    }

    clientSecretBasicAuthenticationMethod(): this {
        this._clientAuthMethods.client_secret_basic = new ClientSecretBasic();
        return this;
    }

    clientSecretPostAuthenticationMethod(): this {
        this._clientAuthMethods.client_secret_post = new ClientSecretPost();
        return this;
    }

    noneAuthenticationMethod(): this {
        this._clientAuthMethods.none = new NoneAuthMethod();
        return this;
    }

    addClientAuthenticationMethod(
        value: 'client_secret_basic' | 'client_secret_post' | 'none' | ClientAuthMethod
    ): this {
        if (value == 'client_secret_basic') {
            this.clientSecretPostAuthenticationMethod();
        } else if (value == 'client_secret_post') {
            this.clientSecretBasicAuthenticationMethod();
        } else if (value == 'none') {
            this.noneAuthenticationMethod();
        } else {
            this._clientAuthMethods[value.method] = value;
        }
        return this;
    }

    /**
     * 
     * @param ttlSeconds - Lifetime in seconds of the access token. Defaults to 1 hour.
     * @returns 
     */
    setAccessTokenLifetime(ttlSeconds: number = 3600): this {
        this.accessTokenLifetime = ttlSeconds;
        return this;
    }

    getAccessTokenLifetime(): number | undefined {
        return this.accessTokenLifetime;
    }

    setDescription(description: string): this {
        this.description = description;
        return this;
    }

    /**
     *
     * @param scopes The scopes of the access request.
     * A map between the scope name and a short description for it. The map MAY be empty.
     * @returns
     */
    setScopes(scopes: Record<string, string>): this {
        this.scopes = scopes;
        return this;
    }

    getScopes(): Record<string, string> | undefined {
        return this.scopes;
    }

    getSecuritySchemeName(): string {
        return this.securitySchemeName;
    }

    getDescription(): string | undefined {
        return this.description;
    }

    /**
     * Where authentication schemes and strategies are registered.
     */
    /*
    integrateStrategy(t: KaapiTools): void {
        const tokenTypePrefix = this.tokenType;
        const tokenTypeInstance = this._tokenType;
        const getJwtAuthority = () => this.getJwtAuthority();

        t.scheme(this.securitySchemeName, (_server, options) => {
            return {
                async authenticate(request, h) {
                    const settings: OAuth2AuthOptions = Hoek.applyToDefaults({}, options || {});

                    const authorization = request.raw.req.headers.authorization;

                    const authSplit = authorization ? authorization.split(/\s+/) : ['', ''];

                    const tokenType = authSplit[0];
                    let jwtAccessTokenPayload: JWTPayload | undefined;

                    if (tokenType.toLowerCase() !== tokenTypePrefix.toLowerCase()) {
                        return Boom.unauthorized(null, tokenTypePrefix);
                    }

                    const token = authSplit[1];

                    if (!(await tokenTypeInstance.isValid(request, token)).isValid) {
                        return Boom.unauthorized(null, tokenTypePrefix);
                    }

                    const jwtAuthority = getJwtAuthority();

                    if (jwtAuthority && settings.useAccessTokenJwks) {
                        try {
                            jwtAccessTokenPayload = await jwtAuthority.verify(token);
                        } catch (err) {
                            t.log.error(err);
                            return Boom.unauthorized(null, tokenTypePrefix);
                        }
                    }

                    if (settings.validate) {
                        try {
                            const result = await settings.validate?.(request, { token, jwtAccessTokenPayload }, h);

                            if (result && 'isAuth' in result) {
                                return result;
                            }

                            if (result && 'isBoom' in result) {
                                return result;
                            }

                            if (result) {
                                const { isValid, credentials, artifacts, message } = result;

                                if (isValid && credentials) {
                                    return h.authenticated({ credentials, artifacts });
                                }

                                if (message) {
                                    return h.unauthenticated(Boom.unauthorized(message, tokenTypePrefix), {
                                        credentials: credentials || {},
                                        artifacts,
                                    });
                                }
                            }
                        } catch (err) {
                            return Boom.internal(err instanceof Error ? err : `${err}`);
                        }
                    }

                    return Boom.unauthorized(null, tokenTypePrefix);
                },
            };
        });
        t.strategy(this.securitySchemeName, this.securitySchemeName, this.options);
    }
        */

    abstract token(request: Request): Promise<OAuth2AuthFlowTokenResponse>;
}