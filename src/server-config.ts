import { RateLimit } from "./rate-limiter";

interface ServerConfig {
    dbFile?: string;
    devMode: boolean;
    csrf: {
        formTimeout: number;
        secret: Buffer;
    };
    httpHosts: string[];
    httpOrigins: string[];
    logRequests: boolean;
    password: string;
    privateResourcesRoot: string;
    rates: {
        authGlobal: RateLimit;
        authPerIp: RateLimit;
    };
    serverPort: number;
    sessionTimeout: number;
    tls: {
        certFile: string;
        keyFile: string;
    };
}

export default function readServerConfig(): ServerConfig {
    function parseStringWithDefaultAndExplicitUndefined(s: string | undefined, defaultValue: string): string | undefined {
        if (s === undefined)
            return defaultValue;
        return s === "" ? undefined : s;
    }

    function parseRateLimit(s: string | undefined): RateLimit | null {
        if (s === undefined)
            return null;
        const [bucketCapacity, windowSize] = s
            .split(";", 2)
            .map(parseInt);
        if (!Number.isFinite(bucketCapacity) || !Number.isFinite(windowSize))
            throw new Error("invalid rate limit numbers");
        return {
            bucketCapacity,
            windowSize,
        };
    }

    const serverPort = parseInt(process.env.HTTP_PORT || "8080");
    return {
        dbFile: parseStringWithDefaultAndExplicitUndefined(process.env.G9_DB_FILE, "db.json"),
        devMode: process.env.NODE_ENV === "development",
        csrf: {
            formTimeout: parseInt(process.env.G9_FORM_TIMEOUT || "300"),
            secret: Buffer.from(process.env.G9_CSRF_SECRET || "VGhpcyBpcyBhIHZlcnkgaW5zZWN1cmUgQ1NSRiBzZWNyZXQga2V5", "base64"),
        },
        httpHosts: (process.env.G9_HOSTS || `localhost:${serverPort}`).split(","),
        httpOrigins: (process.env.G9_HTTP_ORIGIN || `https://localhost:${serverPort}`).split(","),
        logRequests: process.env.G9_LOG_REQUESTS !== "0",
        password: process.env.G9_PASSWD || "insecure-password",
        privateResourcesRoot: process.env.G9_PRIV_ROOT || "private-res",
        rates: {
            authGlobal: parseRateLimit(process.env.G9_RATE_AUTH_GLOBAL) ?? { bucketCapacity: 128, windowSize: 60 * 60 },
            authPerIp: parseRateLimit(process.env.G9_RATE_AUTH_PER_IP) ?? { bucketCapacity: 32, windowSize: 60 * 60 * 12 },
        },
        serverPort,
        sessionTimeout: parseInt(process.env.G9_SESS_TIMEOUT || "43200"),
        tls: {
            keyFile: process.env.G9_TLS_KEY_FILE || "dev-private-key.pem",
            certFile: process.env.G9_TLS_CERT_FILE || "dev-cert.pem",
        },
    };
}
