export function base64UrlSafeEncode(buffer: Buffer) {
    return buffer.toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}
