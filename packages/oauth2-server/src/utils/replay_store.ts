export interface ReplayStore<T extends string | number> {
    has(value: T): Promise<boolean>;
    delete(value: T): Promise<void>;
    add(value: T, ttlSeconds: number): Promise<void>;
}

export class InMemoryReplayStore<T extends string | number = string | number> implements ReplayStore<T> {
    private values: Record<string, number> = {};

    async has(value: T): Promise<boolean> {
        if (this.values[`${value}`]) {
            return await Promise.resolve(true);
        }
        return await Promise.resolve(false);
    }

    async delete(value: T): Promise<void> {
        delete this.values[`${value}`];
        return await Promise.resolve();
    }

    async add(value: T, ttlSeconds: number): Promise<void> {
        const to = this.values[`${value}`];
        if (to) {
            clearTimeout(to);
        }
        this.values[`${value}`] = setTimeout(async () => {
            await this.delete(value);
        }, ttlSeconds * 1000);

        return await Promise.resolve();
    }
}

export type ReplayDetector = ReplayStore<string>;

export function createInMemoryReplayStore<T extends string | number = string | number>(): InMemoryReplayStore<T> {
    return new InMemoryReplayStore<T>();
}
