import { ClientAuthMethod, ClientAuthMethodResponse } from "./types.ts";

export class ClientSecretPost implements ClientAuthMethod {
    get method(): 'client_secret_post' {
        return 'client_secret_post';
    }

    get secretIsOptional(): boolean {
        return false;
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
                client_id: form.get("client_id"),
                client_secret: form.get("client_secret"),
            };
        } else if (contentType.includes("application/json")) {
            body = req.json ? await req.json() : null;
        } else {
            body = null;
        }

        if (
            body &&
            typeof body === 'object' &&
            'client_id' in body &&
            'client_secret' in body
        ) {
            res.hasAuthMethod = true;
            if (typeof body.client_id === 'string') res.clientId = body.client_id;
            if (typeof body.client_secret === 'string') res.clientSecret = body.client_secret;
        }

        return res;
    }
}