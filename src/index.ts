import type {} from '@fastify/cookie';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { ZodError } from 'zod';
import { configurePassport, getConfig, type PassportConfigInput } from './lib/config.ts';
import { registerNetworkRoutes } from './routes/networks.ts';
import { ApiError } from './lib/types.ts';
export { migrate } from './lib/migrate.ts';
export { closePool } from './lib/db.ts';
export { ApiError } from './lib/types.ts';
export type { NetworkProvider } from './lib/network-accounts.ts';
export interface AuthenticatedPrincipal { principalId: string; }
export interface PassportRoutesOptions extends PassportConfigInput {
  /** Must verify a host-owned session. Never return browser-claimed identities. */
  authenticate(request: FastifyRequest): Promise<AuthenticatedPrincipal | null>;
}
export async function registerPassportRoutes(app: FastifyInstance, options: PassportRoutesOptions): Promise<void> {
  configurePassport(options);
  if (!app.hasRequestDecorator('cookies')) throw Error('Register @fastify/cookie before the Passport plugin.');
  if (typeof options.authenticate !== 'function') throw Error('A host-authenticated session adapter is required.');
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof ApiError) return reply.status(error.statusCode).send({ error: error.code, message: error.message, ...(error.statusCode === 401 ? { signInUrl: getConfig().signInUrl } : {}) });
    if (error instanceof ZodError) return reply.status(400).send({ error: 'invalid_payload', message: 'Connection fields are invalid.' });
    // Do not serialize provider errors, request URLs, authorization codes or credentials.
    request.log.warn({ code: 'passport_request_failed' }, 'Passport operation did not complete');
    return reply.status(500).send({ error: 'passport_request_failed', message: 'The Passport operation could not complete. Check the provider and try again.' });
  });
  registerNetworkRoutes(app, { requireSession: async request => {
    const principal = await options.authenticate(request);
    if (!principal || typeof principal.principalId !== 'string' || !principal.principalId.trim() || principal.principalId.length > 200 || /[\u0000-\u001f\u007f]/.test(principal.principalId)) throw new ApiError(401, 'unauthenticated', 'Sign in with the host application before connecting networks.');
    return { principalId: principal.principalId };
  } });
}
