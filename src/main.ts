// See TS file and line number in error stack traces
require("source-map-support").install();

import * as crypto from "crypto";
import * as fs from "fs";
import * as http2 from "http2";
import * as path from "path";
import * as querystring from "querystring";
import * as util from "util";

import { totp } from "notp";
import * as qrcode from "qrcode";

import { readAuthRequest, AuthResponseType } from "./auth-request";
import { readCookies } from "./cookies";
import { base64UrlSafeEncode, base32Encode } from "./encoding";
import Http2Server from "./http2-server";
import { Logger, LogType } from "./logger";
import { LoadFromDiskResult } from "./persistable-module";
import { PortalAssets } from "./portal-assets";
import { PortalTemplates } from "./portal-templates";
import { RateLimiter } from "./rate-limiter";
import { sendOptionsResponse, sendRobotsTxtResponse, sendLogInPage, sendPrivatePngImage, sendPortalAssetFile, sendPrivateResourceFile, sendLogInJsonResponse } from "./http2-response";
import readServerConfig from "./server-config";
import { TemporaryTokenDb } from "./temporary-token-db";

const cryptoRandomBytes = util.promisify(crypto.randomBytes);

const config = readServerConfig();
const server = new Http2Server(fs.readFileSync(config.tls.keyFile), fs.readFileSync(config.tls.certFile), Logger.ROOT);
const portalAssets = new PortalAssets(config.devMode, Logger.ROOT);
const portalTemplates = new PortalTemplates(config.devMode, portalAssets);
const sessionTokens = new TemporaryTokenDb(config.session.timeout * 1000, config.session.tokenDbFile);
const rateLimiter = new RateLimiter(config.rates.authGlobal, config.rates.authPerIp, config.rates.dbFile);

function readRequestHost(req: http2.Http2ServerRequest): string | undefined {
    if (req.httpVersionMajor === 1) {
        return req.headers.host;
    } else {
        return req.headers[":authority"];
    }
}

async function tryHandleTotpQrCodeRequest(req: http2.Http2ServerRequest, res: http2.Http2ServerResponse, queryStr: string, l: Logger): Promise<boolean> {
    let query = null;
    try {
        query = querystring.parse(queryStr);
    } catch (err) {
        l.log(LogType.Info, "totp_qr_code_query_weird", { err });
        return false;
    }

    if (typeof query.token !== "string") {
        l.log(LogType.Info, "totp_qr_code_query_token_missing");
        return false;
    }

    if (query.token.length >= 512) {
        l.log(LogType.Info, "totp_qr_code_query_token_too_large");
        return false;
    }

    try {
        const data = Buffer.from(query.token, "base64");
        const actualDigest = data.subarray(0, 32);
        const expiresAtBuffer = data.subarray(32, 40);

        const hmac = crypto.createHmac("sha256", config.totp.qrCodeUrlKey);
        hmac.update(expiresAtBuffer);
        const expectedDigest = hmac.digest();

        if (!actualDigest.equals(expectedDigest)) {
            l.log(LogType.Warn, "totp_qr_code_query_token_forged");
            return false;
        }

        const expiresAt = new Date(expiresAtBuffer.readDoubleLE(0));
        if (new Date() >= expiresAt) {
            l.log(LogType.Info, "totp_qr_code_query_token_expired");
            return false;
        }
    } catch (err) {
        l.log(LogType.Info, "totp_qr_code_query_token_weird", { err });
        return false;
    }

    const issuer = encodeURIComponent(config.totp.issuer);
    const accountName = encodeURIComponent(config.totp.accountName);
    const totpUrl = `otpauth://totp/${issuer}:${accountName}?secret=${base32Encode(config.totp.key)}&issuer=${issuer}`;
    const buffer = await qrcode.toBuffer(totpUrl, { scale: 10 });
    // Send the image file to the client
    sendPrivatePngImage(req, res, buffer);
    return true;
}

async function handleRequest(req: http2.Http2ServerRequest, res: http2.Http2ServerResponse, l: Logger) {
    const ip = req.socket.remoteAddress;
    if (ip === undefined) {
        l.log(LogType.Critical, "http_request_ip_undefined", { origin: req.headers.origin });
        res.socket.destroy();
        return;
    }

    if (config.logRequest)
        l.log(LogType.Info, "http_request", { ip, method: req.method, url: req.url });

    // Make sure that the Host header is correct
    const host = readRequestHost(req);
    if (host === undefined || !config.allowedHosts.includes(host)) {
        l.log(LogType.Warn, "http_request_bad_host", { got: host ?? null });
        res.socket.destroy();
        return;
    }

    if (req.method === "OPTIONS") {
        sendOptionsResponse(res);
        return;
    }

    const queryStartIndex = req.url.indexOf("?");
    
    let urlWithoutQuery;
    if (queryStartIndex === -1) {
        urlWithoutQuery = req.url;
    } else {
        urlWithoutQuery = req.url.substring(0, queryStartIndex);
    }
    urlWithoutQuery = decodeURIComponent(urlWithoutQuery);

    if (!urlWithoutQuery.startsWith("/")) {
        l.log(LogType.Warn, "http_url_no_slash_prefix");
        res.socket.destroy();
        return;
    }

    if (urlWithoutQuery === "/robots.txt") {
        sendRobotsTxtResponse(req, res);
        return;
    }

    // Allow authenticated users to generate QR-codes
    if (urlWithoutQuery === "/totp-qr-code.png") {
        if (queryStartIndex === -1) {
            l.log(LogType.Info, "totp_qr_code_query_missing");
        } else {
            if (await tryHandleTotpQrCodeRequest(req, res, req.url.substring(queryStartIndex + 1), l))
                return;
        }
    }

    const file = portalAssets.getFileFromUrl(urlWithoutQuery);
    if (file !== undefined) {
        await sendPortalAssetFile(file.hostPath, file.digest, req, res);
        return;
    }

    // Check if the authentication cookie is valid
    const cookies = readCookies(req, l);
    if (cookies === null) {
        res.socket.destroy();
        return;
    }
    const authToken = cookies.sessionToken !== undefined ? sessionTokens.getByValue(cookies.sessionToken) : undefined;
    const isAuthenticated = authToken?.isValid ?? false;

    // Try to authenticate otherwise if the user just submitted the form
    let logInFormError = null;
    if (!isAuthenticated && req.method === "POST") {
        // We shouldn't have a referrer because we disable it on the form page.
        // If we have one, then either the browser is dumb or the submission is
        // coming from a page on another site.
        if (req.headers.referer) {
            let correctOrigin;
            try {
                correctOrigin = config.httpOrigins.includes(new URL(req.headers.referer).origin);
            } catch (err) {
                correctOrigin = false;
            }
            if (!correctOrigin) {
                l.log(LogType.Warn, "auth_unexpected_referrer", { referrer: req.headers.referer });
                res.socket.destroy();
                return;
            }
        }

        // Check if the Origin header says that the request comes from a page
        // on our site.
        if (req.headers.origin !== undefined && !config.httpOrigins.includes(req.headers.origin)) {
            l.log(LogType.Warn, "auth_unexpected_origin", { origin: req.headers.origin });
            res.socket.destroy();
            return;
        }

        // Read and parse the request's body
        const body = await readAuthRequest(req, l);
        if (body === null) {
            res.socket.destroy();
            return;
        }
        
        // Validate the TOTP
        const totpWithoutSpaces = body.totp.replace(/\s/g, "");
        const totpValid = totpWithoutSpaces.length === 6 &&
            [...totpWithoutSpaces].every(c => c >= '0' && c <= '9');
        if (!totpValid) {
            // Do not log the whole body as this could happen if the user uses an
            // old browser which doesn't support client-side validation and in that
            // case, we don't want to log the password.
            l.log(LogType.Warn, "auth_request_body_weird_totp", { totp: body.totp });
        }

        let isFromJs = body.responseType === AuthResponseType.Json;

        // Check anti-CSRF token
        if (cookies.antiCsrfNonce === undefined) {
            l.log(LogType.Warn, "auth_request_no_anti_csrf_nonce");
            res.socket.destroy();
            return;
        }
        if (cookies.antiCsrfNonce.length >= 512) {
            l.log(LogType.Warn, "auth_request_anti_csrf_nonce_too_large");
            res.socket.destroy();
            return;
        }
        let antiCsrfNonceBuffer;
        try {
            antiCsrfNonceBuffer = Buffer.from(cookies.antiCsrfNonce, "base64");
        } catch (err) {
            l.log(LogType.Warn, "auth_request_anti_csrf_nonce_weird");
            res.socket.destroy();
            return;
        }
        if (body.antiCsrfToken.length >= 512) {
            l.log(LogType.Warn, "auth_request_body_anti_csrf_token_too_large");
            res.socket.destroy();
            return;
        }
        let antiCsrfValid = false;
        let formExpired = null;
        try {
            const buffer = Buffer.from(body.antiCsrfToken, "base64");
            const actualDigest = buffer.subarray(0, 32);
            const formTimeoutBuffer = buffer.subarray(32, 40);

            const hmac = crypto.createHmac("sha256", config.csrf.secret);
            hmac.update(antiCsrfNonceBuffer);
            hmac.update(formTimeoutBuffer);
            const expectedDigest = hmac.digest();

            antiCsrfValid = actualDigest.equals(expectedDigest);
            if (antiCsrfValid) {
                const formTimeout = formTimeoutBuffer.readDoubleLE();

                const now = new Date();
                if (now.getTime() >= formTimeout) {
                    formExpired = new Date(formTimeout);
                }
            }
        } catch (err) {
            l.log(LogType.Warn, "auth_request_body_anti_csrf_token_weird");
            res.socket.destroy();
            return;
        }
        if (!antiCsrfValid) {
            l.log(LogType.Warn, "auth_request_body_anti_csrf_token_forged");
            res.socket.destroy();
            return;
        }
        if (formExpired !== null) {
            l.log(LogType.Info, "auth_request_body_anti_csrf_token_expired");
            res.socket.destroy();
            return;
        }
        if (isFromJs && req.headers["custom-header-for-csrf-prevention"] !== "1") {
            l.log(LogType.Info, "auth_request_custom_anti_csrf_header_missing");
            res.socket.destroy();
            return;
        }

        let success = false;
        if (logInFormError === null && body.password !== "" && totpValid) {
            if (!rateLimiter.validate(ip)) {
                l.log(LogType.Warn, "auth_rate_limited");
            } else {
                // Validate the credentials.
                // Note: do not short circuit to make timing attacks harder (but
                // still possible).
                success = true;
                success = body.password === config.password && success;
                success = totpWithoutSpaces === totp.gen(config.totp.key) && success;

                if (success) {
                    l.log(LogType.Info, "auth_success");
                    rateLimiter.resetPunishments(ip);
                } else {
                    l.log(LogType.Info, "auth_failed");
                    rateLimiter.punish(ip);
                }
            }
        }

        if (success) {
            // Authenticate the user
            const sessionToken = await sessionTokens.makeOrGetFreshToken();
            const sessionTokenStr = encodeURIComponent(sessionToken.value);
            res.setHeader("Set-Cookie", `__Host-session-token=${sessionTokenStr}; Path=/; Secure; HttpOnly; SameSite=Strict`);

            if (!isFromJs) {
                // Redirect to the same page to prevent the "Confirm Form
                // Resubmission" dialog
                res.writeHead(303, { "Location": req.url });
                res.end();
                return;
            }
        } else if (logInFormError === null) {
            logInFormError = "credentials";
        }

        if (isFromJs) {
            sendLogInJsonResponse(req, res, logInFormError);
            return;
        }
    }

    if (isAuthenticated) {
        if (!authToken!!.isFresh) {
            // Renew the authentication token
            const sessionToken = await sessionTokens.makeOrGetFreshToken();
            const sessionTokenStr = encodeURIComponent(sessionToken.value);
            res.setHeader("Set-Cookie", `__Host-session-token=${sessionTokenStr}; Secure; HttpOnly; SameSite=Strict`);
        }

        let filePath = config.privateResourcesRoot;
        for (let part of urlWithoutQuery.substring(1).split("/")) {
            if (part === "." || part === "..") {
                l.log(LogType.Warn, "http_url_dotdot");
                res.socket.destroy();
                return;
            }
            filePath = path.join(filePath, part);
        }

        // Send the private resource
        await sendPrivateResourceFile(filePath, req, res);
    } else {
        const antiCsrfNonce = await cryptoRandomBytes(16);
        res.setHeader("Set-Cookie", `__Host-anti-csrf-nonce=${base64UrlSafeEncode(antiCsrfNonce)}; Path=/; Secure; HttpOnly; SameSite=Strict`);

        const formTimeout = new Date().getTime() + 1000 * config.csrf.formTimeout;
        const formTimeoutBuffer = Buffer.alloc(8);
        formTimeoutBuffer.writeDoubleLE(formTimeout);

        const hmac = crypto.createHmac("sha256", config.csrf.secret);
        hmac.update(antiCsrfNonce);
        hmac.update(formTimeoutBuffer);
        const digest = hmac.digest();

        const antiCsrfToken = Buffer.alloc(40);
        antiCsrfToken.set(digest, 0);
        antiCsrfToken.set(formTimeoutBuffer, 32);

        // Send the authentication page
        const logInPage = await portalTemplates.render("log-in.html.njk", {
            credentialsErrorClass: "class=\"form-error" + (logInFormError === "credentials" ? "" : " hidden") + "\"",
            csrfErrorClass: "class=\"form-error" + (logInFormError === "csrf" ? "" : " hidden") + "\"",
            antiCsrfToken: base64UrlSafeEncode(antiCsrfToken),
        });
        sendLogInPage(req, res, logInPage);
    }
}

server.handleRequest = handleRequest;

Promise.all([
    portalAssets.add("css/log-in.css"),
    portalAssets.add("js/log-in.js"),
    sessionTokens.loadFromDisk()
        .then(result => {
            if (result === LoadFromDiskResult.FileNotFound)
                Logger.ROOT.log(LogType.Warn, "session_tokens_db_file_missing");
        }),
    rateLimiter.loadFromDisk()
        .then(result => {
            if (result === LoadFromDiskResult.FileNotFound)
                Logger.ROOT.log(LogType.Warn, "auth_rate_db_file_missing");
        }),
]).then(async () => {
    await server.listen(config.serverPort);
    Logger.ROOT.log(LogType.Info, "http_listening");
}).catch(err => {
    Logger.ROOT.log(LogType.Critical, "start_fail", { err: Logger.formatError(err) });

    // TODO: why do we have to exit here?
    process.exit(1);
});

async function gracefulShutdown() {
    Logger.ROOT.log(LogType.Info, "http_closing");
    await server.close();

    Logger.ROOT.log(LogType.Info, "persisting");
    await Promise.all([sessionTokens.saveToDisk(), rateLimiter.saveToDisk()]);
}
let isShuttingDown = false;
function gracefulShutdownWrapper() {
    if (isShuttingDown)
        return;
    isShuttingDown = true;

    gracefulShutdown()
        .then(() => {
            // TODO: why do we have to exit here?
            process.exit(0);
        })
        .catch(err => {
            Logger.ROOT.log(LogType.Critical, "graceful_exit_fail", { err: Logger.formatError(err) });
            // TODO: why do we have to exit here?
            process.exit(1);
        });
}
process.on("SIGTERM", gracefulShutdownWrapper);
process.on("SIGINT", gracefulShutdownWrapper);
