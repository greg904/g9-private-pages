import base32Encode from "base32-encode";
import * as crypto from "crypto";
import * as dotenv from "dotenv";
import * as fs from "fs";
import * as http2 from "http2";
import { totp } from "notp";
import send from "send";
import * as querystring from "querystring";
import * as qrcode from "qrcode";

import RateLimiter from "./rate-limiter";

// Read environment variables from .env file
dotenv.config();

if (!process.env.APP_NAME) {
    console.error("you must set the application name through the APP_NAME environment variable");
    process.exit(1);
}

if (!process.env.APP_PASSWD) {
    console.error("you must set a password through the APP_PASSWD environment variable");
    process.exit(1);
}

if (!process.env.APP_TOTP_KEY) {
    console.error("you must set a TOTP key through the APP_TOTP_KEY environment variable");
    process.exit(1);
}
const totpKey = Buffer.from(process.env.APP_TOTP_KEY, "base64");
const totpKeyBase32 = base32Encode(totpKey, "RFC4648");

const sessionSecret = crypto.randomBytes(16).toString("base64");

const internalNamespace = crypto.randomBytes(16).toString("base64");

const server = http2.createSecureServer({
    key: fs.readFileSync("localhost-private-key.pem"),
    cert: fs.readFileSync("localhost-cert.pem"),
    allowHTTP1: true,
});

const rateLimiter = new RateLimiter();

class BadRequestError extends Error {
    constructor(message?: string) {
        super(message);
    }
}

function readRequestBody(req: http2.Http2ServerRequest): Promise<Buffer> {
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
                    req.destroy(new BadRequestError("chunk from request is not a Buffer"));
                    return;
                }
                if (byteCount + chunk.length >= 512) {
                    req.destroy(new BadRequestError("request body is too large"));
                    return;
                }
                chunks.push(chunk);
                byteCount += chunk.length;
            }
        });
        req.on("error", reject);
    });
}

function checkAuthentication(req: http2.Http2ServerRequest) {
    if (req.headers.cookie !== undefined) {
        if (req.headers.cookie.length >= 512)
            throw new BadRequestError("HTTP request cookie header is too large");

        let secret: string | null = null;

        for (let cookieStr of req.headers.cookie.split(";")) {
            const parts = cookieStr.split("=", 2);
            if (parts.length !== 2)
                throw new BadRequestError("invalid HTTP request cookie");
            if (parts[0].trim() !== "secret")
                continue;
            secret = decodeURIComponent(parts[1].trim());
            break;
        }

        if (secret === sessionSecret)
            return true;
    }
    return false;
}

async function handleRequest(req: http2.Http2ServerRequest, res: http2.Http2ServerResponse) {
    // enable HSTS
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");

    if (req.method === "OPTIONS") {
        res.writeHead(204, { "Allow": "GET, POST, HEAD, OPTIONS" });
        res.end();
        return;
    }

    let authenticated = false;
    let authenticationError = false;

    // Check if the authentication cookie is valid
    if (checkAuthentication(req))
        authenticated = true;

    // Try to authenticate otherwise if the user just submitted the form
    if (!authenticated && req.method === "POST") {
        // Read and parse the request's body
        const bodyStr = (await readRequestBody(req)).toString();
        const body = querystring.parse(bodyStr);
        
        // Validate the request body
        if (body.password === null || typeof body.password !== "string" ||
            body.totp === null || typeof body.totp !== "string")
            throw new BadRequestError("invalid log in request body");

        const ip = req.socket.remoteAddress;
        if (ip === undefined)
            throw new Error("socket IP is undefined");
        if (!rateLimiter.validateAuthRequest(ip)) {
            console.log(`user with IP=${req.socket.remoteAddress} was rate limited`);
            authenticationError = true;
        } else {
            // Validate the credentials.
            // Note: do not short circuit to make timing attacks harder (but
            // still possible).
            let success = true;
            success = success && body.password === process.env.APP_PASSWD;
            success = success && body.totp.replace(/\s/g, "") === totp.gen(totpKey);

            if (success) {
                // Authenticate the user and redirect to the same page to prevent
                // the "Confirm Form Resubmission" dialog
                console.log(`user with IP=${req.socket.remoteAddress} has successfully authenticated`);
                rateLimiter.resetPunishments(ip);
                res.writeHead(303, {
                    "Set-Cookie": `secret=${encodeURIComponent(sessionSecret)}; Secure; HttpOnly`,
                    "Location": req.url,
                });
                res.end();
                return;
            } else {
                console.log(`user with IP=${req.socket.remoteAddress} has failed authentication`);
                rateLimiter.punishAuthFailure(ip);
                authenticationError = true;
            }
        }
    }

    if (authenticated) {
        // Allow authenticated users to generate QR-codes
        const urlWithoutQuery = req.url.replace(/\?.*$/, "");
        if (urlWithoutQuery === `/${internalNamespace}/totp-qrcode.png`) {
            const issuer = encodeURIComponent(process.env.APP_NAME!);
            const totpUrl = `otpauth://totp/${issuer}:Page%20access?secret=${totpKeyBase32}&issuer=${issuer}`;
            const imageBuffer = await qrcode.toBuffer(totpUrl, { scale: 1, margin: 0 });
            const headers = {
                "Content-Type": "image/png",
                "Content-Length": imageBuffer.length,
            };
            if (req.method === "HEAD") {
                res.writeHead(204, headers);
                res.end();
            } else {
                res.writeHead(200, headers);
                res.end(imageBuffer);
            }
            return;
        } else if (urlWithoutQuery === "/.totp-qrcode.html") {
            let qrCodePage = await fs.promises.readFile("static/qr-code.html", { encoding: "utf-8" });

            // Set the correct link to the QR-code image
            qrCodePage = qrCodePage.replace("<qr-code-link>", `/${internalNamespace}/totp-qrcode.png`);

            // Send the page
            const headers = {
                "Content-Type": "text/html",
                "Content-Length": qrCodePage.length,
                "Content-Security-Policy": "default-src 'none'; style-src-elem 'unsafe-inline'; img-src 'self' data:",
            };
            if (req.method === "HEAD") {
                res.writeHead(204, headers);
                res.end();
            } else {
                res.writeHead(200, headers);
                res.end(qrCodePage);
            }
            return;
        }

        // Send the private resource
        send(req, req.url, { root: "example-pages" })
            .pipe(res as unknown as NodeJS.WritableStream);
    } else {
        let logInPage = await fs.promises.readFile("static/log-in.html", { encoding: "utf-8" });

        if (!authenticationError) {
            // Remove the error sections in the page
            logInPage = logInPage.replace(/<!-- error start -->.*<!-- error end -->/s, "");
        }

        // Send the authentication page
        const headers = {
            "Content-Type": "text/html",
            "Content-Length": logInPage.length,
            "Content-Security-Policy": "default-src 'none'; style-src-elem 'unsafe-inline'; img-src data:",
        };
        if (req.method === "HEAD") {
            res.writeHead(204, headers);
            res.end();
        } else {
            res.writeHead(200, headers);
            res.end(logInPage);
        }
    }
}

function sendErrorResponse(err: any, res: http2.Http2ServerResponse) {
    if (!res.stream.writableEnded) {
        let errorCode;
        let errorMsg;

        if (err instanceof BadRequestError) {
            errorCode = 400;
            errorMsg = "Your client sent an invalid request.";
        } else {
            errorCode = 500;
            errorMsg = "An unexpected server error has occurred.";
        }

        // Reply to the client with a vague error message.
        if (!res.headersSent) {
            res.writeHead(errorCode, {
                "Content-Type": "text/plain",
                "Content-Length": errorMsg.length,
            });
        }
        res.end(errorMsg);
    }
}

server.on("request", function(req, res) {
    let promise: Promise<void>;
    try {
        promise = handleRequest(req, res);
    } catch (err) {
        // Also wrap immediate errors (that are thrown when the Promise
        // constructor is ran) into a promise to prevent errors from leaking
        // from the request handler.
        promise = Promise.reject(err);
    }

    promise.catch(function(err) {
        console.log(`got error ${err} while handling request for client with IP=${req.socket.remoteAddress}`);
        sendErrorResponse(err, res);
    });
});

server.on("error", function(err) {
    console.error("got error on server", err);
});

server.listen(8080, function() {
    console.log("server is listening...");
});
