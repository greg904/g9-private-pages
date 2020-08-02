import * as fs from "fs";

export const enum LoadFromDiskResult {
    Success,
    FileNotFound,
}

export abstract class PersistableModule {
    private readonly persistFile?: string;
    
    constructor(persistFile?: string) {
        this.persistFile = persistFile;
    }

    abstract loadFromJson(json: any): void;
    abstract toJson(): any;

    async loadFromDisk() {
        if (this.persistFile === undefined)
            return;

        let dataStr;
        try {
            dataStr = await fs.promises.readFile(this.persistFile, { encoding: "utf8" });
        } catch (err) {
            if (err !== null && err.code === "ENOENT")
                return LoadFromDiskResult.FileNotFound;
            throw err;
        }

        // Deserialize the data from the file and load it
        const data = JSON.parse(dataStr);
        this.loadFromJson(data);

        return LoadFromDiskResult.Success;
    }

    async saveToDisk() {
        if (this.persistFile === undefined)
            return;

        // Serialize the data
        const data = this.toJson();
        const dataStr = JSON.stringify(data);

        await fs.promises.writeFile(this.persistFile, dataStr);
    }
}
