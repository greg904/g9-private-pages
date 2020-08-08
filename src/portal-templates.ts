import * as path from "path";

import * as nunjucks from "nunjucks";

import { PortalAssets } from "./portal-assets";

export  class PortalTemplates {
    private static ROOT = path.join(path.dirname(__dirname), "dist", "templates");

    private readonly env: nunjucks.Environment;

    constructor(hotReload: boolean, assets: PortalAssets) {
        const fsLoader = new nunjucks.FileSystemLoader(PortalTemplates.ROOT, {
            watch: hotReload,
        });

        this.env = new nunjucks.Environment(fsLoader, {
            throwOnUndefined: true,
        
            // Remove ugly whitespace
            trimBlocks: true,
            lstripBlocks: true,
        
            // Hot reload of templates
            watch: hotReload,
        });
        
        this.env.addGlobal("assetUrlByName", function(name: string) {
            return assets.getUrlForAsset(name);
        });
    }

    render(name: string, context?: object): Promise<string> {
        return new Promise((resolve, reject) => {
            this.env.render(name, context, function(err, res) {
                if (res === null) {
                    reject(err);
                } else {
                    resolve(res);
                }
            });
        });
    }
}
