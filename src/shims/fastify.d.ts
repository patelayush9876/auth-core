declare module 'fastify' {
  export interface FastifyRequest {
    headers: Record<string, string | string[] | undefined>;
    cookies?: Record<string, string | undefined>;
    body?: unknown;
    ip?: string;
  }

  export interface FastifyReply {
    header(name: string, value: unknown): unknown;
    status(code: number): FastifyReply;
    send(payload: unknown): unknown;
    redirect(statusCode: number, url: string): unknown;
  }

  export type FastifyPluginCallback = (...args: any[]) => unknown;
}

