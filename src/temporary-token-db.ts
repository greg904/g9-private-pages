import * as crypto from "crypto";
import * as util from "util";

import { base64UrlSafeEncode } from "./encoding";
import { Persistable } from "./persistable";

const cryptoRandomBytes = util.promisify(crypto.randomBytes);

export class Token {
    readonly value: string;
    readonly freshUntil: Date;
    readonly validUntil: Date;

    constructor(value: string, freshUntil: Date, validUntil: Date) {
        this.value = value;
        this.freshUntil = freshUntil;
        this.validUntil = validUntil;
    }

    get isFresh() {
        return new Date().getTime() < this.freshUntil.getTime();
    }

    get isValid() {
        return new Date().getTime() < this.validUntil.getTime();
    }
}

/**
 * Generate a token, send it to the client, forget about it. Later when the
 * client comes back with a token, check if the token was forged by the client,
 * or if it expired (the lifetime of a token is specified in the constructor).
 * 
 * To save memory, tokens actually live (and therefore are considered valid) a
 * little bit longer than the lifetime specified in the constructor so that we
 * can hand out to a client a token that was already handed out to someone
 * earlier but whose remaining lifetime is still greater that the lifetime
 * specified in the constructor.
 */
export class TemporaryTokenDb extends Persistable {
    private static MAX_VALID_TOKEN_COUNT = 32;

    private readonly tokens: Token[] = [];
    private readonly minTokenLife: number;
    private readonly tokenFreshnessDuration: number;

    constructor(minTokenLife: number, persistFile?: string) {
        super(persistFile);
        this.minTokenLife = minTokenLife;
        this.tokenFreshnessDuration = this.minTokenLife /
            (TemporaryTokenDb.MAX_VALID_TOKEN_COUNT - 1);
    }

    getByValue(value: string) {
        return this.tokens.find(t => t.value === value);
    }

    async makeOrGetFreshToken() {
        if (this.tokens.length !== 0) {
            // Reuse the previously generated token if it is still fresh
            const lastGeneratedToken = this.tokens[this.tokens.length - 1];
            if (lastGeneratedToken.isFresh)
                return lastGeneratedToken;

            // Otherwise, we'll need to make a new one, but first, let's
            // remove expired tokens.
            this.removeExpiredTokens();
        }

        // Generate a new token and store it for validation later
        const token = await this.createNewToken();
        this.tokens.push(token);

        return token;
    }

    loadFromJson(json: any) {
        // Empty the array
        this.tokens.length = 0;

        for (let entry of json)
            this.tokens.push(new Token(entry.v, new Date(entry.f), new Date(entry.e)));
    }

    toJson() {
        // Use a short format to save space
        return this.tokens.map(t => {
            return {
                v: t.value,
                f: t.freshUntil.getTime(),
                e: t.validUntil.getTime(),
            };
        });
    }

    private async createNewToken() {
        const value = base64UrlSafeEncode(await cryptoRandomBytes(16));

        const now = new Date();
        const freshUntil = new Date(now.getTime() + this.tokenFreshnessDuration);
        const validUntil = new Date(now.getTime() + this.tokenFreshnessDuration + this.minTokenLife);
        return new Token(value, freshUntil, validUntil);
    }

    private removeExpiredTokens() {
        while (this.tokens.length !== 0) {
            if (this.tokens[0].isValid)
                break;
            this.tokens.shift();
        }
    }
}
