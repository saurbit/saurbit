import { ClientAuthMethod, ClientAuthMethodResponse } from "./types.ts";

export class NoneAuthMethod implements ClientAuthMethod {
    get method(): 'none' {
        return 'none';
    }

    get secretIsOptional(): boolean {
        return true;
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
            };
        } else if (contentType.includes("application/json")) {
            body = req.json ? await req.json() : null;
        } else {
            body = null;
        }

        if (body && typeof body === 'object' && 'client_id' in body && typeof body.client_id === 'string') {
            res.hasAuthMethod = true;
            if (typeof body.client_id === 'string') res.clientId = body.client_id;
        }

        return res;
    }
}