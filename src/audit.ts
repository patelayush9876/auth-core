import { EventEmitter } from 'node:events';
import type { AuditEvent, AuditEventName } from './types/index.js';

/**
 * Typed audit event emitter.
 * Default delivery is synchronous EventEmitter.
 * Override with an async hook by calling `setAsyncHandler`.
 *
 * @example
 * ```ts
 * auditEmitter.on('user.login', (event) => {
 *   logger.info(event);
 * });
 * ```
 */
class AuditEmitter extends EventEmitter {
  private asyncHandler?: (event: AuditEvent) => Promise<void>;

  /**
   * Override the default EventEmitter delivery with an async handler.
   * The handler is awaited before continuing — use for reliable delivery.
   */
  setAsyncHandler(handler: (event: AuditEvent) => Promise<void>): void {
    this.asyncHandler = handler;
  }

  /**
   * Emit a structured audit event.
   * If an async handler is set, it is awaited; otherwise EventEmitter.emit is called.
   */
  async emitAudit(event: AuditEvent): Promise<void> {
    if (this.asyncHandler) {
      await this.asyncHandler(event);
    } else {
      this.emit(event.event, event);
      this.emit('*', event);
    }
  }
}

export const auditEmitter = new AuditEmitter();
// Increase max listeners for apps that subscribe to many event types
auditEmitter.setMaxListeners(50);

/**
 * Build and emit an audit event.
 */
export async function emitAudit(
  event: AuditEventName,
  fields: Omit<AuditEvent, 'event' | 'timestamp'>,
): Promise<void> {
  const auditEvent: AuditEvent = {
    event,
    timestamp: new Date(),
    ...fields,
  };
  await auditEmitter.emitAudit(auditEvent);
}
