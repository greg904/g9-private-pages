import * as fs from "fs";

export const enum LoadFromDiskResult {
    /**
     * Either the file was loaded and deserialized successfully from disk, or
     * there was no file to load because <code>undefined</code> was passed to
     * the constructor.
     */
    Success,

    /**
     * The file was not found.
     */
    FileNotFound,
}

export interface Persistable {
    /**
     * Loads the state from a JSON object.
     * @param json the JSON object
     */
    loadFromJson(json: any): void;

    /**
     * Converts the state that needs to be persisted to a JSON object and
     * returns it.
     * @returns the JSON object
     */
    toJson(): any;
}

export class PersistManager {
    private readonly persistables = new Map<string, Persistable>();
    private readonly persistFile?: string;

    constructor(persistFile?: string) {
        this.persistFile = persistFile;
    }

    /**
     * Adds a Persistable to be loaded from disk and saved to disk later.
     * @param key a unique name for this Persistable
     * @param persistable the Persistable to add
     */
    add(key: string, persistable: Persistable) {
        if (this.persistables.has(key))
            throw new Error("there is already one persistable with that key");

        this.persistables.set(key, persistable);
    }

    async loadFromDisk(): Promise<LoadFromDiskResult> {
        if (this.persistFile === undefined)
            return LoadFromDiskResult.Success;

        let dataStr;
        try {
            dataStr = await fs.promises.readFile(this.persistFile, { encoding: "utf8" });
        } catch (err) {
            if (err !== null && err.code === "ENOENT")
                return LoadFromDiskResult.FileNotFound;
            throw err;
        }

        const data = JSON.parse(dataStr);
        for (let [key, persistable] of this.persistables.entries()) {
            if (data[key] !== undefined)
                persistable.loadFromJson(data[key]);
        }

        return LoadFromDiskResult.Success;
    }

    async saveToDisk() {
        if (this.persistFile === undefined)
            return;

        const data = Object.fromEntries(
            Array.from(this.persistables, ([key, persistable], _i) => {
                return [key, persistable.toJson()];
            })
        );
        const dataStr = JSON.stringify(data);

        await fs.promises.writeFile(this.persistFile, dataStr);
    }
}
