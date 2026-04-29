declare module 'express' {
  export interface Request {
    headers: Record<string, string | string[] | undefined>;
    cookies?: Record<string, string | undefined>;
    body?: unknown;
    ip?: string;
    get(name: string): string | undefined;
  }

  export interface Response {
    setHeader(name: string, value: unknown): void;
    status(code: number): Response;
    json(body: unknown): Response;
    redirect(statusOrUrl: number | string, url?: string): void;
  }

  export type NextFunction = (err?: unknown) => void;
  export type RequestHandler = (req: Request, res: Response, next: NextFunction) => unknown;
}

