import * as fs from "fs";
import * as http2 from "http2";
import * as path from "path";
import * as stream from "stream";
import * as util from "util";

import * as mime from "mime-types";

const fsFstat = util.promisify(fs.fstat);
const streamPipeline = util.promisify(stream.pipeline);

const BASE_HEADERS: http2.OutgoingHttpHeaders = {
    // HSTS
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
};

/**
 * We will have different behaviors for the different parts of the web site.
 * 
 * We will be more strict with our own content and more lax with the user
 * uploaded content (the private resources).
 */
const enum SecurityMode {
    Strict,
    Default,
}

const enum CacheControl {
    // Should not be cached at all
    Forbid,

    // Should not be cached very long because it's private
    Private,

    CacheForever,
}

function writeHeadHelper(req: http2.Http2ServerRequest, res: http2.Http2ServerResponse, statusCode: number, securityMode: SecurityMode, cacheControl: CacheControl, contentType: string | undefined, contentLength: number, etag: string | undefined, additionalHeaders: http2.OutgoingHttpHeaders = {}) {
    if (req.method === "HEAD" && statusCode === http2.constants.HTTP_STATUS_OK)
        statusCode = http2.constants.HTTP_STATUS_NO_CONTENT;

    const headers: http2.OutgoingHttpHeaders = {
        ...BASE_HEADERS,

        [http2.constants.HTTP2_HEADER_CONTENT_LENGTH]: contentLength,

        // Disable Referrer on the portal because we don't need it
        [http2.constants.HTTP2_HEADER_REFERER]: securityMode === SecurityMode.Strict ? "no-referrer" : "strict-origin",
        // Prevent someone from puting the page in an iframe because it can be scary
        // to the user and we don't need it anyway
        "X-Frame-Options": securityMode === SecurityMode.Strict ? "DENY" : "SAMEORIGIN",
        // Force the client to not guess the Content-Type from the content and
        // instead use the one that we sent it. Note: this shouldn't improve
        // security but we don't really need the client to guess the Content-Type
        // anyway so let's not make it waste energy. Also, it makes some security
        // audits happier.
        "X-Content-Type-Options": "nosniff",

        ...additionalHeaders,
    };

    if (contentType !== undefined)
        headers[http2.constants.HTTP2_HEADER_CONTENT_TYPE] = contentType;

    if (etag !== undefined)
        headers[http2.constants.HTTP2_HEADER_ETAG] = `"${etag}"`;

    switch (cacheControl) {
    case CacheControl.Forbid:
        headers[http2.constants.HTTP2_HEADER_CACHE_CONTROL] = "no-store";
        break;
    case CacheControl.Private:
        headers[http2.constants.HTTP2_HEADER_CACHE_CONTROL] = "private; max-age=60";
        break;
    case CacheControl.CacheForever:
        headers[http2.constants.HTTP2_HEADER_CACHE_CONTROL] = "max-age=31536000";
        break;
    }

    res.writeHead(statusCode, headers);
}

function writeHelper(req: http2.Http2ServerRequest, res: http2.Http2ServerResponse, statusCode: number, securityMode: SecurityMode, cacheControl: CacheControl, contentType: string | undefined, content: Buffer, etag: string | undefined, additionalHeaders: http2.OutgoingHttpHeaders = {}) {
    writeHeadHelper(req, res, statusCode, securityMode, cacheControl, contentType, content.length, etag, additionalHeaders);

    if (req.method === "HEAD") {
        // No Content
        res.end();
    } else {
        res.end(content);
    }
}

async function sendFile(req: http2.Http2ServerRequest, res: http2.Http2ServerResponse, file: string, securityMode: SecurityMode, cacheControl: CacheControl, etag: string | undefined, additionalHeaders: http2.OutgoingHttpHeaders = {}) {
    let fileHandle;
    try {
        fileHandle = await fs.promises.open(file, "r");
    } catch (err) {
        if (err !== null && err !== undefined && err.code === "ENOENT") {
            send404(req, res);
            return;
        }
        throw err;
    }

    try {
        const stats = await fsFstat(fileHandle.fd);
        if (!stats.isFile()) {
            send404(req, res);
            return;
        }

        const contentType = mime.contentType(path.extname(file));
        writeHeadHelper(req, res, 200, securityMode, cacheControl, contentType ? contentType : undefined, stats.size, etag, additionalHeaders);

        if (req.method === "HEAD") {
            res.end();
        } else {
            // Stream the file's content to the client
            const fileStream = fs.createReadStream("", { fd: fileHandle.fd, autoClose: false });
            await streamPipeline(fileStream, res as unknown as NodeJS.WritableStream);
        }
    } finally {
        await fileHandle.close();
    }
}

// Disallow crawling for every page
const ROBOTS_TXT_BUFFER = Buffer.from("User-agent: *\nDisallow: /\n");

const ERROR_404_BUFFER = Buffer.from("The requested file was not found.\n");

export function sendPermanentRedirection(to: string, res: http2.Http2ServerResponse) {
    res.writeHead(http2.constants.HTTP_STATUS_MOVED_PERMANENTLY, {
        ...BASE_HEADERS,

        // Allowed methods
        [http2.constants.HTTP2_HEADER_LOCATION]: to,
    });
    res.end();
}

/**
 * Sends the response that we return when we receive a request with the OPTIONS
 * method.
 */
export function sendOptionsResponse(res: http2.Http2ServerResponse) {
    res.writeHead(http2.constants.HTTP_STATUS_NO_CONTENT, {
        ...BASE_HEADERS,

        // Allowed methods
        [http2.constants.HTTP2_HEADER_ALLOW]: "GET, POST, HEAD, OPTIONS",
    });
    res.end();
}

export function sendRobotsTxtResponse(req: http2.Http2ServerRequest, res: http2.Http2ServerResponse) {
    writeHelper(req, res, SecurityMode.Strict, 200, CacheControl.CacheForever, "text/plain; charset=utf-8", ROBOTS_TXT_BUFFER, "robots_txt");
}

export function send404(req: http2.Http2ServerRequest, res: http2.Http2ServerResponse) {
    writeHelper(req, res, 404, SecurityMode.Strict, CacheControl.Forbid, "text/plain; charset=utf-8", ERROR_404_BUFFER, "error_404");
}

export function sendPortalPage(req: http2.Http2ServerRequest, res: http2.Http2ServerResponse, html: string) {
    writeHelper(req, res, 200, SecurityMode.Strict, CacheControl.Forbid, "text/html; charset=utf-8", Buffer.from(html), undefined, {
        "Content-Security-Policy": "default-src 'none'; connect-src 'self'; script-src 'self'; style-src 'self'; img-src data:; form-action 'self'; navigate-to 'none'; block-all-mixed-content; trusted-types",
        // Block everything
        "Permissions-Policy": "accelerometer 'none'; ambient-light-sensor 'none'; autoplay 'none'; battery 'none'; camera 'none'; display-capture 'none'; document-domain 'none'; encrypted-media 'none'; geolocation 'none'; fullscreen 'none'; execution-while-not-rendered 'none'; execution-while-out-of-viewport 'none'; gyroscope 'none'; magnetometer 'none'; microphone 'none'; midi 'none'; navigation-override 'none'; payment 'none'; picture-in-picture 'none'; publickey-credentials-get 'none'; sync-xhr 'none'; usb 'none'; wake-lock 'none'; web-share 'none'; xr-spatial-tracking 'none'",
        "X-XSS-Protection": "1; mode=block",
    });
}

export function sendLogInJsonResponse(req: http2.Http2ServerRequest, res: http2.Http2ServerResponse, json: any) {
    writeHelper(req, res, 200, SecurityMode.Strict, CacheControl.Forbid, "application/x-log-in-response; charset=utf-8", Buffer.from(JSON.stringify(json)), undefined);
}

export function sendPortalAssetFile(file: string, etag: string, req: http2.Http2ServerRequest, res: http2.Http2ServerResponse) {
    return sendFile(req, res, file, SecurityMode.Strict, CacheControl.CacheForever, etag);
}

export function sendPrivateResourceFile(file: string, req: http2.Http2ServerRequest, res: http2.Http2ServerResponse) {
    return sendFile(req, res, file, SecurityMode.Default, CacheControl.Private, undefined);
}
