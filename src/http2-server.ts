import * as http2 from "http2";
import * as net from "net";

import { LogType, Logger, LogContext } from "./logger";

class Http2RequestLogContext implements LogContext {
    private readonly req: http2.Http2ServerRequest;

    constructor(req: http2.Http2ServerRequest) {
        this.req = req;
    }

    toJson() {
        return {
            type: "http2_server_request",
            ip: this.req.socket.remoteAddress
        };
    }
}

export default class Http2Server {
    private static SOCKET_ID_COUNTER = 0;

    private readonly actualServer: http2.Http2SecureServer;
    private readonly logger: Logger;
    private readonly openSockets = new Map<number, net.Socket>();
    private overrideErrorHandler: ((err: Error) => void) | null = null;
    handleRequest?: (req: http2.Http2ServerRequest, res: http2.Http2ServerResponse, l: Logger) => Promise<void>;

    constructor(tlsKey: Buffer, tlsCert: Buffer, logger: Logger) {
        this.actualServer = http2.createSecureServer({
            key: tlsKey,
            cert: tlsCert,
            allowHTTP1: true,
        });
        this.logger = logger;

        this.actualServer.on("connection", (socket: net.Socket) => {
            // Store the open socket so that we can close them all when we want
            // to close the server
            const id = Http2Server.SOCKET_ID_COUNTER++;
            this.openSockets.set(id, socket);
            socket.on("close", () => this.openSockets.delete(id));
        });
        this.actualServer.on("error", err => {
            if (this.overrideErrorHandler === null) {
                this.logger.log(LogType.Critical, "http_server_error", { err: Logger.formatError(err) });
            } else {
                this.overrideErrorHandler(err);
            }
        });
        this.actualServer.on("request", (req, res) => {
            if (this.handleRequest === undefined) {
                this.logger.log(LogType.Critical, "http_server_no_handler");
                res.socket.destroy();
                return;
            }

            const l = this.logger.pushContext(new Http2RequestLogContext(req));

            let promise: Promise<void>;
            try {
                promise = this.handleRequest(req, res, l);
            } catch (err) {
                // Also wrap immediate errors (that are thrown when the Promise
                // constructor is ran) into a promise to prevent errors from leaking
                // from the request handler.
                promise = Promise.reject(err);
            }
    
            promise.catch(err => {
                l.log(LogType.Critical, "general_error", { err: Logger.formatError(err) });

                // Directly close the socket because the client is suspicious
                req.socket.destroy();
            });
        });
    }

    listen(port: number) {
        return new Promise((resolve, reject) => {
            this.overrideErrorHandler = err => {
                this.overrideErrorHandler = null;
                reject(err);
            }
            this.actualServer.listen(port, () => {
                this.overrideErrorHandler = null;
                resolve();
            });
        });
    }

    close() {
        return new Promise((resolve, reject) => {
            let timedOut = false;

            // Give the server 8 seconds to close
            setTimeout(() => {
                this.logger.log(LogType.Critical, "http_close_time_out");
                resolve();

                timedOut = true;
            }, 8000);

            // Close all open sockets so that the server can actually close
            if (this.openSockets.size > 0) {
                this.logger.log(LogType.Info, "http_close_open_sockets", { count: this.openSockets.size });

                for (let socket of this.openSockets.values())
                    socket.destroy();
            }

            this.actualServer.close(err => {
                if (timedOut)
                    return;

                if (err) {
                    reject(err);
                } else {
                    resolve();
                }
            });
        })
    }
}
