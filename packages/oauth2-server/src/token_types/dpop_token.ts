import { JwkVerify } from "../utils/jwt_authority.ts";
import { InMemoryReplayStore, ReplayDetector } from "../utils/replay_store.ts";
import type { TokenType, TokenTypeValidationResponse } from "./types.ts";

export type DPoPTokenTypeValidation = (
    request: Request,
    token: string,
    tokenLifetime: number
) => TokenTypeValidationResponse | Promise<TokenTypeValidationResponse>;

export type DPoPTokenTypeRequestValidation = (
    req: Request,
    tokenLifetime: number
) => TokenTypeValidationResponse | Promise<TokenTypeValidationResponse>;

export class DPoPTokenType implements TokenType {
    #handler: DPoPTokenTypeValidation;
    #tokenRequestHandler: DPoPTokenTypeRequestValidation;
    #tokenLifetime: number = 300;
    #replayDetector: ReplayDetector;

    get prefix(): 'DPoP' {
        return 'DPoP';
    }

    get configuration() {
        return {
            dpop_signing_alg_values_supported: ['ES256'],
            require_dpop: true,
        };
    }

    #jwkVerify: JwkVerify;

    constructor(
        jwkVerify: JwkVerify,
        replayDetector?: ReplayDetector
    ) {
        this.#jwkVerify = jwkVerify;
        this.#replayDetector = replayDetector ?? new InMemoryReplayStore<string>();
        this.#handler = async (req: Request, token, tokenLifetime: number) => {
            if (!token) return { isValid: false, message: 'Missing token' };
            return await this._handleDefault(req, tokenLifetime);
        };

        this.#tokenRequestHandler = async (req: Request, tokenLifetime: number) => {
            return await this._handleDefault(req, tokenLifetime);
        };
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    private async _handleDefault(req: Request, tokenLifetime: number): Promise<TokenTypeValidationResponse> {
        const dpopHeader = req.headers.get('DPoP');
        if (!dpopHeader || typeof dpopHeader != 'string')
            return { message: 'Missing Demonstration of Proof-of-Possession', isValid: false };

        try {
            const payload = await this.#jwkVerify(
                dpopHeader,
                { algorithms: ['ES256'] }
            );

            if (payload.htm !== req.method.toUpperCase()) return { message: 'HTM mismatch', isValid: false };

            const url = new URL(req.url);
            const forwardedProto = req.headers.get('x-forwarded-proto');
            const protocol = forwardedProto ? forwardedProto : url.protocol.replace(':', '');
            const fullUrl = protocol + '://' + url.host + url.pathname;
            if (payload.htu !== fullUrl) return { message: 'HTU mismatch', isValid: false };

            const now = Math.floor(Date.now() / 1000);

            if (!payload.iat) return { message: 'Missing IAT', isValid: false };
            if (Math.abs(now - payload.iat) > tokenLifetime) return { message: 'Proof expired', isValid: false };

            if (!payload.jti) return { message: 'Missing JTI', isValid: false };

            if (await this.#replayDetector.has(payload.jti)) return { message: 'Replay detected', isValid: false };
            await this.#replayDetector.add(payload.jti, tokenLifetime);

            return { isValid: true, dpopPayload: payload };
        } catch (err) {
            return { message: `${err}`, isValid: false };
        }
    }

    setReplayDetector(value: ReplayDetector): this {
        this.#replayDetector = value;
        return this;
    }

    /**
     * Set the token lifetime for DPoP proofs (in seconds). Default is 300 seconds (5 minutes).
     * @param tokenLifetime - token lifetime for DPoP proofs (in seconds)
     */
    setTokenLifetime(tokenLifetime: number): this {
        this.#tokenLifetime = tokenLifetime;
        return this;
    }

    validateTokenRequest(handler: DPoPTokenTypeRequestValidation): this {
        this.#tokenRequestHandler = handler;
        return this;
    }

    validate(handler: DPoPTokenTypeValidation): this {
        this.#handler = handler;
        return this;
    }

    async isValidTokenRequest(req: Request): Promise<TokenTypeValidationResponse> {
        return await this.#tokenRequestHandler(req, this.#tokenLifetime);
    }

    async isValid(req: Request, token: string): Promise<TokenTypeValidationResponse> {
        return await this.#handler(req, token, this.#tokenLifetime);
    }
}