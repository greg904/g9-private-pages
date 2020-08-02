import * as util from "util";

export const enum LogType {
    Info,
    // This can happen, but it's suspicious
    Warn,
    // This should have never happened, a fix needs to be done
    Critical,
}

interface LogOptions {
    readonly typeStr: string;
    readonly stderr: boolean;
}

function getOptionsFromLogType(type: LogType): LogOptions {
    switch (type) {
        case LogType.Info:
            return { typeStr: "info", stderr: false };
        case LogType.Warn:
            return { typeStr: "warn", stderr: false };
        case LogType.Critical:
            return { typeStr: "critical", stderr: false };
    }
}

export interface LogContext {
    toJson(): any;
}

export class Logger {
    static readonly ROOT = new Logger([]);

    private readonly contexts: ReadonlyArray<LogContext>;

    private constructor(contexts: ReadonlyArray<LogContext>) {
        this.contexts = contexts;
    }

    log(type: LogType, event: string, additionalData?: any) {
        const options = getOptionsFromLogType(type);
        const data = {
            type: options.typeStr,
            event,
            additionalData,
            contexts: this.contexts.map(c => c.toJson()),
        };
        const fn = options.stderr ? console.error : console.log;
        fn(JSON.stringify(data));
    }

    pushContext(context: LogContext) {
        return new Logger([...this.contexts, context]);
    }

    static formatError(error: any) {
        if (error === null || error === undefined) {
            return error;
        } else if (typeof error.stack === "string") {
            return error.stack;
        } else {
            return util.inspect(error);
        }
    }
}
