#!/usr/bin/node

const argv = require("minimist")(process.argv.slice(2));
if (!argv.key) {
    console.error("You must specify the QR-code URL key!");
    process.exit(1);
}

const tokenLifetime = parseInt(argv.lifetime || "120");
const expiresAt = new Date().getTime() + tokenLifetime * 1000;
const expiresAtBuffer = Buffer.alloc(8);
expiresAtBuffer.writeDoubleLE(expiresAt);

const crypto = require("crypto");
const hash = crypto.createHmac("sha256", Buffer.from(argv.key, "base64"));
hash.update(expiresAtBuffer);
const digest = hash.digest();

const token = Buffer.alloc(40);
token.set(digest, 0);
token.set(expiresAtBuffer, 32);

function base64UrlSafeEncode(buffer) {
    return buffer.toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

const origin = argv.origin || "https://localhost:8080";
console.log(`${origin}/totp-qr-code.png?token=${base64UrlSafeEncode(token)}`);
