export function base64UrlSafeEncode(buffer: Buffer) {
    return buffer.toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

export function base32Encode(buffer: Buffer) {
    const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let result = "";

    // From https://github.com/LinusU/base32-encode
    let view = 0;
    let bitsAvailable = 0;
    for (let i = 0; i < buffer.length; i++) {
        view = ((view << 8) | buffer.readUInt8(i)) & 4095;
        bitsAvailable += 8;

        while (bitsAvailable >= 5) {
            result += ALPHABET[(view >> (bitsAvailable - 5)) & 31];
            bitsAvailable -= 5;
        }
    }
    if (bitsAvailable > 0)
        result += ALPHABET[view & ((1 << bitsAvailable) - 1)];

    return result;
}
