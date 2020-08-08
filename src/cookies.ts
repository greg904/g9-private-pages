import * as http2 from "http2";

import { Logger, LogType } from "./logger";

export interface RequestCookies {
    sessionToken?: string;
    antiCsrfNonce?: string;
}

export function readCookies(req: http2.Http2ServerRequest, l: Logger): RequestCookies | null {
    const result: RequestCookies = {};

    if (req.headers.cookie !== undefined) {
        if (req.headers.cookie.length >= 512) {
            l.log(LogType.Warn, "http_request_cookie_header_too_large");
            return null;
        }

        for (let cookieStr of req.headers.cookie.split(";")) {
            const parts = cookieStr.split("=", 2);
            if (parts.length !== 2) {
                l.log(LogType.Warn, "http_request_cookie_header_invalid");
                return null;
            }
            
            const name = decodeURIComponent(parts[0].trim());
            const value = decodeURIComponent(parts[1].trim());
            if (name === "__Host-session-token") {
                result.sessionToken = value;
            } else if (name === "__Host-anti-csrf-nonce") {
                result.antiCsrfNonce = value;
            }
        }
    }
    return result;
}
