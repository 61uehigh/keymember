import type { FastifyRequest } from "fastify";

/**
 * ### clientIp
 *
 * IP address to record in audit events.
 *
 * @param request Incoming request
 * @returns The client address as Fastify resolved it
 */
export function clientIp(request: FastifyRequest): string {
  return request.ip;
}
