import { JwtDecode, JwtPayload, JwtVerify } from "../utils/jwt_authority.ts";
import { ClientAuthMethod, ClientAuthMethodResponse } from "./types.ts";

export enum ClientSecretJwtAlgorithms {
    HS256 = 'HS256',
    HS384 = 'HS384',
    HS512 = 'HS512',
}

export class ClientSecretJwt implements ClientAuthMethod {
    static algo = ClientSecretJwtAlgorithms;

    get method(): 'client_secret_jwt' {
        return 'client_secret_jwt';
    }

    get secretIsOptional(): boolean {
        return false;
    }

    get algorithms(): ClientSecretJwtAlgorithms[] {
        return this.#algorithms.length ? this.#algorithms : [ClientSecretJwtAlgorithms.HS256];
    }

    #algorithms: ClientSecretJwtAlgorithms[] = [];

    #handler: (clientId: string, decoded: JwtPayload, clientAssertion: string) => Promise<Uint8Array | string | null>;

    /**
     * to avoid adding jose as a dependency for users who don't need JWT client authentication,
     * the JWT decoding and verification logic is injected via the constructor
     */
    #jwtDecode: JwtDecode;

    /**
     * to avoid adding jose as a dependency for users who don't need JWT client authentication,
     * the JWT decoding and verification logic is injected via the constructor
     */
    #jwtVerify: JwtVerify;

    constructor(
        jwtDecode: JwtDecode,
        jwtVerify: JwtVerify
    ) {
        this.#handler = () => Promise.resolve(null);
        this.#jwtDecode = jwtDecode;
        this.#jwtVerify = jwtVerify;
    }

    addAlgorithm(algo: ClientSecretJwtAlgorithms): this {
        if (!this.#algorithms.includes(algo)) {
            this.#algorithms.push(algo);
            this.#algorithms.sort();
        }
        return this;
    }

    getClientSecret(
        handler: (clientId: string, decoded: JwtPayload, clientAssertion: string) => Promise<Uint8Array | string | null>
    ): this {
        this.#handler = handler;
        return this;
    }

    async extractClientCredentials(req: Request): Promise<ClientAuthMethodResponse> {
        const res: ClientAuthMethodResponse = {
            hasAuthMethod: false,
        };

        // Extract info from the request body (either form-urlencoded or JSON)
        let body: unknown;
        const contentType = req.headers.get("content-type") || "";
        if (contentType.includes("application/x-www-form-urlencoded")) {
            const form = await req.formData();
            body = {
                client_assertion_type: form.get("client_assertion_type"),
                client_assertion: form.get("client_assertion"),
            };
        } else if (contentType.includes("application/json")) {
            body = req.json ? await req.json() : null;
        } else {
            body = null;
        }

        if (
            body &&
            typeof body === 'object' &&
            'client_assertion_type' in body &&
            body.client_assertion_type == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' &&
            'client_assertion' in body &&
            typeof body.client_assertion === 'string'
        ) {
            res.hasAuthMethod = true;

            const decoded = await this.#jwtDecode(body.client_assertion);

            if (decoded.aud && typeof decoded.aud === 'string') {
                res.clientId = decoded.aud;
                const clientSecret = await this.#handler(decoded.aud, decoded, body.client_assertion);

                if (clientSecret) {
                    const { payload } = await this.#jwtVerify(
                        body.client_assertion,
                        typeof clientSecret === 'string' ? new TextEncoder().encode(clientSecret) : clientSecret,
                        {
                            algorithms: this.algorithms,
                        }
                    );
                    if (payload) {
                        res.clientSecret =
                            typeof clientSecret === 'string' ? clientSecret : new TextDecoder().decode(clientSecret);
                    }
                }
            }
        }

        return res;
    }
}