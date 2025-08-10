import fastifyJwt from '@fastify/jwt';

declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: { id: number; email: string } // Dados que você envia no token
    user: { id: number; email: string }    // Dados que você recebe no token
  }
}