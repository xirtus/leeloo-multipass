import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import { registerPassportRoutes } from '../dist/index.js';

const app = Fastify({
  bodyLimit: 64 * 1024,
  logger: {
    serializers: {
      req(request) { return { method: request.method, url: request.url?.split('?')[0] }; },
    },
    redact: ['req.headers.cookie', 'req.headers.authorization'],
  },
});
app.register(cookie);
app.register(registerPassportRoutes, {
  // Replace with your verified, host-owned session service. The example denies
  // private operations by default; request headers/body never establish identity.
  authenticate: async () => null,
});
app.get('/login', async (_request, reply) => reply.code(501).send({
  message: 'Integrate your host authentication and session validation first.',
}));
await app.listen({ host: '127.0.0.1', port: 8788 });
