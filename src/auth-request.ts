import * as http2 from "http2";
import * as querystring from "querystring";

import { Logger, LogType } from "./logger";

export interface AuthRequest {
    password: string;
    antiCsrfToken: string;
    responseType: AuthResponseType;
}

export const enum AuthResponseType {
    Html,
    Json,
}

function readRequestBody(req: http2.Http2ServerRequest, l: Logger): Promise<Buffer | null> {
    return new Promise(function(resolve, reject) {
        const chunks: Buffer[] = [];
        let byteCount = 0;
        req.on("readable", function() {
            while (true) {
                const chunk = req.read();
                if (chunk === null) {
                    // End of stream
                    resolve(Buffer.concat(chunks));
                    return;
                }
                if (!(chunk instanceof Buffer)) {
                    l.log(LogType.Critical, "http_request_body_not_buffer");
                    return null;
                }
                if (byteCount + chunk.length >= 512) {
                    l.log(LogType.Warn, "http_request_body_too_large", { current: Buffer.concat(chunks).toString() });
                    return;
                }
                chunks.push(chunk);
                byteCount += chunk.length;
            }
        });
        req.on("error", reject);
    });
}

export async function readAuthRequest(req: http2.Http2ServerRequest, l: Logger): Promise<AuthRequest | null> {
    let responseType = AuthResponseType.Html;
    if (req.headers.accept) {
        if (req.headers.accept.length >= 512) {
            l.log(LogType.Warn, "http_request_accept_too_large");
            return null;
        }
        const types = req.headers.accept.split(",")
            .map(type => type.trim());
        if (types.includes("application/x-log-in-response"))
            responseType = AuthResponseType.Json;
    }

    const bodyBuffer = await readRequestBody(req, l);
    if (bodyBuffer === null)
        return null;
    const bodyStr = bodyBuffer.toString();

    let body;
    try {
        body = querystring.parse(bodyStr);
    } catch (err) {
        l.log(LogType.Warn, "auth_request_body_parse_error", { body: bodyStr, err: Logger.formatError(err) });
        return null;
    }

    // Validate the request body
    if (body["anti-csrf-token"] === null || typeof body["anti-csrf-token"] !== "string" ||
        body.password === null || typeof body.password !== "string") {
        l.log(LogType.Warn, "auth_request_body_type_error", { body: bodyStr });
        return null;
    }

    return {
        password: body.password,
        antiCsrfToken: body["anti-csrf-token"],
        responseType,
    };
}
