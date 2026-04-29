declare module 'hono' {
  export interface Context {
    req: {
      raw: { headers: { entries(): IterableIterator<[string, string]> } };
      header(name: string): string | undefined;
    };
    header(name: string, value: string): void;
    set(key: string, value: unknown): void;
    get(key: string): unknown;
    json(body: unknown, status?: number): unknown;
    redirect(url: string, status?: number): unknown;
  }

  export type MiddlewareHandler = (c: Context, next: () => Promise<void>) => Promise<unknown> | unknown;
}

