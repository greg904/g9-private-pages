import { Persistable } from "./persist";

interface Bucket {
    volume: number;
    readonly clearedAt: Date;
}

export interface RateLimit {
    readonly bucketCapacity: number;
    readonly windowSize: number;
}

export class RateLimiter implements Persistable {
    private static MAX_IP_COUNT = 32;

    private readonly limitGlobal: RateLimit;
    private readonly limitPerIp: RateLimit;
    private globalBucket: Bucket | null = null;
    private readonly clientBuckets = new Map<string, Bucket>();

    constructor(globalLimit: RateLimit, perIpLimit: RateLimit) {
        this.limitGlobal = globalLimit;
        this.limitPerIp = perIpLimit;
    }

    validate(ip: string): boolean {
        const now = new Date();
        function checkBucket(bucket: Bucket, limit: RateLimit) {
            return bucket.volume < limit.bucketCapacity ||
                now >= bucket.clearedAt;
        }

        if (this.globalBucket !== null && !checkBucket(this.globalBucket, this.limitGlobal))
            return false;

        const clientBucket = this.clientBuckets.get(ip);
        if (clientBucket === undefined) {
            // If we're under a DDoS attack, we want to block all new IPs
            return this.clientBuckets.size < RateLimiter.MAX_IP_COUNT;
        }
        return checkBucket(clientBucket, this.limitPerIp);
    }

    punish(ip: string) {
        const clientBucket = this.clientBuckets.get(ip);
        if (clientBucket === undefined || new Date() >= clientBucket.clearedAt) {
            // Make more room for new buckets
            this.purgeBuckets();

            if (clientBucket === undefined && this.clientBuckets.size >= RateLimiter.MAX_IP_COUNT) {
                // Should not happen because the validation would have already
                // failed.
                throw new Error("too many different IPs");
            }

            // Add the new bucket
            this.clientBuckets.set(ip, {
                clearedAt: new Date(new Date().getTime() + this.limitPerIp.windowSize),
                volume: 1,
            });
        } else {
            // Increment the existing bucket's request counnt
            clientBucket.volume++;
        }

        if (this.globalBucket === null || new Date() >= this.globalBucket.clearedAt) {
            this.globalBucket = {
                clearedAt: new Date(new Date().getTime() + this.limitGlobal.windowSize),
                volume: 1,
            };
        } else {
            this.globalBucket.volume++;
        }
    }

    resetPunishments(ip: string) {
        this.clientBuckets.delete(ip);
    }

    loadFromJson(json: any) {
        function bucketFromJson(json: any): Bucket {
            return { volume: json.v, clearedAt: new Date(json.c) };
        }

        this.globalBucket = json.globalBucket !== null ? bucketFromJson(json.globalBucket) : null;

        if (Object.keys(json.clientBuckets).length > RateLimiter.MAX_IP_COUNT)
            throw new Error("too many client buckets");
        
        // Deserialize the object into the client bucket map
        this.clientBuckets.clear();
        for (let ip in json.clientBuckets)
            this.clientBuckets.set(ip, bucketFromJson(json.clientBuckets[ip]));
    }

    toJson() {
        function bucketToJson(bucket: Bucket) {
            return { v: bucket.volume, c: bucket.clearedAt.getTime() };
        }

        // Only keep the interesting buckets
        this.purgeBuckets();

        return {
            globalBucket: this.globalBucket !== null ? bucketToJson(this.globalBucket) : null,
            clientBuckets: Object.fromEntries(
                Array.from(this.clientBuckets, ([key, value], _i) => {
                    return [key, bucketToJson(value)];
                })
            ),
        };
    }

    private purgeBuckets() {
        const now = new Date();
        for (let [ip, bucket] of this.clientBuckets.entries()) {
            if (now >= bucket.clearedAt)
                this.clientBuckets.delete(ip);
        }
    }
}
