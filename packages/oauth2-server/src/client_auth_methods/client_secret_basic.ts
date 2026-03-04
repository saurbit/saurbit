import { ClientAuthMethod, ClientAuthMethodResponse } from "./types.ts";

// Fast path for Node/Bun
declare const Buffer: {
    from(input: string, encoding: string): { toString(encoding: string): string };
};

function decodeBase64(b64: string): string {
    // Fast path for Node/Bun
    if (typeof Buffer !== "undefined") {
        return Buffer.from(b64, "base64").toString("utf8");
    }

    // Universal Web API path
    const binary = atob(b64);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
}


export class ClientSecretBasic implements ClientAuthMethod {
    get method(): 'client_secret_basic' {
        return 'client_secret_basic';
    }

    get secretIsOptional(): boolean {
        return false;
    }

    extractClientCredentials(request: Request): ClientAuthMethodResponse {
        const res: ClientAuthMethodResponse = {
            hasAuthMethod: false,
        };

        const authorization = request.headers.get("authorization");

        const [authType = '', base64Credentials = ''] = authorization ? authorization.split(/\s+/) : ['', ''];

        if (authType.toLowerCase() == 'basic') {
            res.hasAuthMethod = true;

            const [clientId, clientSecret] = decodeBase64(base64Credentials).split(":");

            if (clientId) {
                res.clientId = clientId;
            }
            if (clientSecret) {
                res.clientSecret = clientSecret;
            }
        }

        return res;
    }
}