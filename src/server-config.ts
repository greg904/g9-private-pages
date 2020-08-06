import { RateLimit } from "./rate-limiter";

interface ServerConfig {
    readonly devMode: boolean;
    readonly serverPort: number;
    readonly allowedHosts: ReadonlyArray<string>;
    readonly httpOrigins: ReadonlyArray<string>;
    readonly password: string;
    readonly privateResourcesRoot: string;
    readonly logRequest: boolean;
    readonly totp: {
        readonly key: Buffer;
        readonly qrCodeUrlKey: Buffer;
        readonly issuer: string;
        readonly accountName: string;
    }
    readonly tls: {
        readonly keyFile: string;
        readonly certFile: string;
    };
    readonly csrf: {
        readonly secret: Buffer;
        readonly formTimeout: number;
    };
    readonly session: {
        readonly timeout: number;
        readonly tokenDbFile?: string;
    };
    readonly rates: {
        readonly authGlobal: RateLimit;
        readonly authPerIp: RateLimit;
        readonly dbFile?: string;
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
        devMode: process.env.NODE_ENV === "development",
        serverPort,
        allowedHosts: (process.env.G9_HOSTS || `localhost:${serverPort}`).split(","),
        httpOrigins: (process.env.G9_HTTP_ORIGIN || `https://localhost:${serverPort}`).split(","),
        password: process.env.G9_PASSWD || "insecure-password",
        privateResourcesRoot: process.env.G9_PRIV_ROOT || "private-res",
        logRequest: process.env.G9_LOG_REQUESTS !== "0",
        totp: {
            key: Buffer.from(process.env.G9_TOTP_KEY || "VGhpcyBpcyBhIHZlcnkgaW5zZWN1cmUgVE9UUCBrZXk=", "base64"),
            qrCodeUrlKey: Buffer.from(process.env.G9_TOTP_QR_CODE_URL_KEY || "VGhpcyBpcyBhIHZlcnkgaW5zZWN1cmUgVE9UUCBRUi1jb2RlIFVSTCBrZXk=", "base64"),
            issuer: process.env.G9_TOTP_ISSUER || "ExampleApp",
            accountName: process.env.G9_TOTP_ACCOUNT_NAME || "resource-access",
        },
        tls: {
            keyFile: process.env.G9_TLS_KEY_FILE || "dev-private-key.pem",
            certFile: process.env.G9_TLS_CERT_FILE || "dev-cert.pem",
        },
        csrf: {
            secret: Buffer.from(process.env.G9_CSRF_SECRET || "VGhpcyBpcyBhIHZlcnkgaW5zZWN1cmUgQ1NSRiBzZWNyZXQga2V5", "base64"),
            formTimeout: parseInt(process.env.G9_FORM_TIMEOUT || "300"),
        },
        session: {
            timeout: parseInt(process.env.G9_SESS_TIMEOUT || "43200"),
            tokenDbFile: parseStringWithDefaultAndExplicitUndefined(process.env.G9_SESS_TOKEN_DB_FILE, "sess-token-db.json"),
        },
        rates: {
            authGlobal: parseRateLimit(process.env.G9_RATE_AUTH_GLOBAL) ?? { bucketCapacity: 128, windowSize: 60 * 60 },
            authPerIp: parseRateLimit(process.env.G9_RATE_AUTH_PER_IP) ?? { bucketCapacity: 32, windowSize: 60 * 60 * 12 },
            dbFile: parseStringWithDefaultAndExplicitUndefined(process.env.G9_RATE_DB_FILE, "rate-db.json"),
        },
    };
}
