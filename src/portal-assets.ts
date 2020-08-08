import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import * as stream from "stream";
import * as util from "util";

import { base64UrlSafeEncode } from "./encoding";
import { Logger, LogType } from "./logger";

const streamPipeline = util.promisify(stream.pipeline);

function getExtension(file: string) {
    const lastDotIndex = file.lastIndexOf(".");
    if (lastDotIndex === -1)
        return "";
    const lastSlashIndex = file.lastIndexOf("/");
    return lastDotIndex > lastSlashIndex ? file.substring(lastDotIndex) : "";
}

export interface AssetFile {
    readonly hostPath: string;
    readonly digest: string;
}

export class PortalAssets {
    private static ROOT = path.join(__dirname, "assets");

    private readonly urlByNameMap = new Map<string, string>();
    private readonly filePathByUrlMap = new Map<string, string>();
    private readonly hotReload: boolean;
    private readonly logger: Logger;

    constructor(hotReload: boolean, logger: Logger) {
        this.hotReload = hotReload;
        this.logger = logger;
    }

    async add(name: string) {
        const filePath = path.join(PortalAssets.ROOT, ...name.split("/"));

        // Compute a hash of the file's content
        let digest = await PortalAssets.computeDigest(filePath);

        // Create an URL based on that hash, keeping the file's extention
        const extension = getExtension(name);
        let url = `/${digest}${extension}`;

        this.urlByNameMap.set(name, url);
        this.filePathByUrlMap.set(url, filePath);

        this.logger.log(LogType.Info, "assets_add", { name, url });

        // Watch file changes for hot reloading (only if enabled)
        if (!this.hotReload)
            return;
        const watcher = fs.watch(filePath);
        let delayTimeout: NodeJS.Timeout | null = null;
        watcher.on("change", (_eventType, _filename) => {
            const update = () => {
                // When the file changes, recompute the hash and update the map
                PortalAssets.computeDigest(filePath)
                    .then(newDigest => {
                        if (newDigest === digest)
                            return;

                        this.urlByNameMap.delete(name);
                        this.filePathByUrlMap.delete(url);

                        digest = newDigest;
                        url = `/${digest}${extension}`;

                        this.urlByNameMap.set(name, url);
                        this.filePathByUrlMap.set(url, filePath);

                        this.logger.log(LogType.Info, "assets_hot_reload_move", { name, url });
                    })
                    .catch(err => {
                        this.logger.log(LogType.Critical, "assets_hot_reload_fail_compute_hash", { err: Logger.formatError(err) });
                    });
            }

            // Debounce updates
            if (delayTimeout !== null)
                return;
            delayTimeout = setTimeout(() => {
                update();
                delayTimeout = null;
            }, 200);
        });
    }

    /**
     * Returns the URL that corresponds to an asset given its name.
     * @param name the asset name
     */
    getUrlForAsset(name: string) {
        return this.urlByNameMap.get(name);
    }

    /**
     * Gets the path to the file (on the host) to serve for an HTTP request with
     * the specified URL.
     * @param url the HTTP request URL
     * @returns information about the file on the host to serve
     */
    getFileFromUrl(url: string): AssetFile | undefined {
        const filePath = this.filePathByUrlMap.get(url);
        if (filePath === undefined)
            return undefined;
        return {
            hostPath: filePath,
            digest: url.substring(1, url.lastIndexOf(".")),
        };
    }

    private static async computeDigest(filePath: fs.PathLike) {
        const fileStream = fs.createReadStream(filePath);
        const hash = crypto.createHash("sha256");
        await streamPipeline(fileStream, hash);
        return base64UrlSafeEncode(hash.digest().slice(0, 16));
    }
}
