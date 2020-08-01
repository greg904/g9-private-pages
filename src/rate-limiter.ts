class ClientInfo {
    expiresAt: Date;
    authFailureCount = 0;

    constructor() {
        // After some time, we remove the ClientInfo and therefore forget that
        // the client sent us many requests
        const expiryTimeout = 1000 * 60 * 60 * 12;
        this.expiresAt = new Date(new Date().getTime() + expiryTimeout);
    }

    get hasExpired() {
        return new Date().getTime() >= this.expiresAt.getTime();
    }
}

export default class RateLimiter {
    private readonly clientInfoByIp = new Map<string, ClientInfo>();

    validateAuthRequest(ip: string): boolean {
        if (this.isFull)
            return false;
        const clientInfo = this.clientInfoByIp.get(ip);
        if (clientInfo === undefined || clientInfo.hasExpired)
            return true;
        return clientInfo.authFailureCount < 20;
    }

    punishAuthFailure(ip: string) {
        let clientInfo = this.clientInfoByIp.get(ip);
        if (clientInfo !== undefined && clientInfo.hasExpired) {
            clientInfo = new ClientInfo();
            this.clientInfoByIp.set(ip, clientInfo);
        } else if (clientInfo === undefined) {
            if (this.isFull)
                throw new Error("rate limiter is full of IPs");
            clientInfo = new ClientInfo();
            this.clientInfoByIp.set(ip, clientInfo);
        }
        clientInfo.authFailureCount++;
    }

    resetPunishments(ip: string) {
        this.clientInfoByIp.delete(ip);
    }

    private get isFull() {
        return this.clientInfoByIp.size >= 20;
    }
}
