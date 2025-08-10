import fastify, { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import jwt, { FastifyJWT } from '@fastify/jwt';
import swagger from '@fastify/swagger';
import swaggerUI from '@fastify/swagger-ui';
import { Server as SocketIOServer, Socket } from 'socket.io';
import { PrismaClient, Cota } from "@prisma/client";
import { z } from 'zod';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import bcrypt from 'bcryptjs';
import { createCipheriv, createDecipheriv, randomBytes, scrypt } from 'crypto';
import { promisify } from 'util';
import { LoggerOptions } from 'pino';
import { jsonSchemaTransform } from 'fastify-type-provider-zod';

// =================================================================================
// 1. CONFIGURAÇÃO E VARIÁVEIS DE AMBIENTE (com validação Zod)
// =================================================================================

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production']).default('development'),
  PORT: z.coerce.number().default(3001),
  FRONTEND_URL: z.string().url().default('https://ipbfarol.org'),
  DATABASE_URL: z.string().url("DATABASE_URL is required and must be a valid URL."),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters long'),
  ENCRYPTION_KEY: z.string().min(16, 'ENCRYPTION_KEY must be at least 16 characters long'),
});

const env = envSchema.parse(process.env);

// =================================================================================
// 2. TIPAGEM E MÓDULOS GLOBAIS
// =================================================================================

// Augmenta os módulos do Fastify para incluir tipagem customizada
declare module 'fastify' {
  interface FastifyInstance {
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
  interface FastifyRequest {
    user: {
      sub: string; // 'sub' (subject) é o padrão para o ID do usuário no JWT
      email: string;
      isAdmin?: boolean;
    };
  }
}

declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: {
      sub: string;
      email: string;
      isAdmin?: boolean;
    };
    user: {
      sub: string;
      email: string;
      isAdmin?: boolean;
    };
  }
}

// Estende a interface do Socket para incluir dados do usuário autenticado
interface AuthenticatedSocket extends Socket {
    data: {
        user: {
            sub: string;
            email: string;
            isAdmin?: boolean;
        }
    }
}

// =================================================================================
// 3. CLIENTES E SERVIÇOS
// =================================================================================

const prisma = new PrismaClient();

const scryptAsync = promisify(scrypt);
class EncryptionService {
  private readonly algorithm = 'aes-256-ctr';
  private readonly keyLength = 32;
  private readonly ivLength = 16;

  private async getKey(password: string, salt: Buffer): Promise<Buffer> {
    return (await scryptAsync(password, salt, this.keyLength)) as Buffer;
  }

  async encrypt(text: string): Promise<string> {
    const salt = randomBytes(16);
    const iv = randomBytes(this.ivLength);
    const key = await this.getKey(env.ENCRYPTION_KEY, salt);

    const cipher = createCipheriv(this.algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);

    return `${salt.toString('hex')}:${iv.toString('hex')}:${encrypted.toString('hex')}`;
  }

  async decrypt(encryptedData: string): Promise<string> {
    const [saltHex, ivHex, encryptedHex] = encryptedData.split(':');
    if (!saltHex || !ivHex || !encryptedHex) {
      throw new Error("Invalid encrypted data format.");
    }

    const salt = Buffer.from(saltHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const encrypted = Buffer.from(encryptedHex, 'hex');

    const key = await this.getKey(env.ENCRYPTION_KEY, salt);
    const decipher = createDecipheriv(this.algorithm, key, iv);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString('utf8');
  }
}
const encryptionService = new EncryptionService();

// =================================================================================
// 4. ERROS CUSTOMIZADOS E ERROR HANDLER
// =================================================================================

class HttpError extends Error {
  constructor(public statusCode: number, message: string) {
    super(message);
  }
}

const errorHandler = (error: Error, request: FastifyRequest, reply: FastifyReply) => {
  if (error instanceof z.ZodError) {
    return reply.status(400).send({
      message: 'Validation error',
      errors: error.flatten().fieldErrors,
    });
  }

  if (error instanceof HttpError) {
    return reply.status(error.statusCode).send({ message: error.message });
  }
  
  request.log.error(error);
  return reply.status(500).send({ message: 'Internal Server Error' });
};


// =================================================================================
// 5. ROTAS (como plugins)
// =================================================================================

async function authRoutes(app: FastifyInstance) {
  app.withTypeProvider<ZodTypeProvider>().post('/register', {
    schema: {
      summary: 'Registra um novo usuário',
      tags: ['Auth'],
      security: [], // CORREÇÃO: Define explicitamente que não há segurança para esta rota.
      body: z.object({
        email: z.string().email(),
        password: z.string().min(6),
        name: z.string().optional(),
      }),
      response: { 201: z.object({
        message: z.string(),
        token: z.string(),
        user: z.object({ id: z.string(), email: z.string(), name: z.string().nullable() })
      })}
    }
  }, async (request, reply) => {
    const { email, password, name } = request.body;

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      throw new HttpError(409, 'User with this email already exists.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { email, password: hashedPassword, name: name ?? null },
      select: { id: true, email: true, name: true, isAdmin: true }
    });

    const token = app.jwt.sign({ sub: user.id, email: user.email, isAdmin: user.isAdmin });
    return reply.status(201).send({
      message: 'User registered successfully',
      token,
      user: { id: user.id, email: user.email, name: user.name }
    });
  });

  app.withTypeProvider<ZodTypeProvider>().post('/login', {
    schema: {
      summary: 'Autentica um usuário',
      tags: ['Auth'],
      security: [], // CORREÇÃO: Define explicitamente que não há segurança para esta rota.
      body: z.object({
        email: z.string().email(),
        password: z.string(),
      }),
      response: { 200: z.object({
        message: z.string(),
        token: z.string(),
        user: z.object({ id: z.string(), email: z.string(), name: z.string().nullable() })
      })}
    }
  }, async (request, reply) => {
    const { email, password } = request.body;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.password) {
      throw new HttpError(401, 'Invalid credentials.');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new HttpError(401, 'Invalid credentials.');
    }

    const token = app.jwt.sign({ sub: user.id, email: user.email, isAdmin: user.isAdmin });
    return reply.status(200).send({
      message: 'Login successful',
      token,
      user: { id: user.id, email: user.email, name: user.name }
    });
  });

  app.withTypeProvider<ZodTypeProvider>().get('/profile', {
    onRequest: [app.authenticate],
    schema: {
        summary: 'Obtém o perfil do usuário autenticado',
        tags: ['Auth'],
        security: [{ bearerAuth: [] }],
        response: {
            200: z.object({
                id: z.string(),
                email: z.string(),
                name: z.string().nullable(),
                isAdmin: z.boolean(),
                createdAt: z.date(),
            })
        }
    }
  }, async (request, reply) => {
    const userProfile = await prisma.user.findUnique({
      where: { id: request.user.sub },
      select: { id: true, email: true, name: true, isAdmin: true, createdAt: true }
    });

    if (!userProfile) {
      throw new HttpError(404, 'User not found.');
    }
    return reply.send(userProfile);
  });
}

// --- Helper para rotas de Cota ---
const decryptedCotaSchema = z.object({
    id: z.string(),
    valor: z.number(),
    createdAt: z.date(),
    name: z.string().nullable(),
    cpf: z.string().nullable(),
    comprovante: z.string().nullable(),
    observacoes: z.string().nullable(),
});

async function formatCotaResponse(cota: Cota): Promise<z.infer<typeof decryptedCotaSchema>> {
    const sensitiveData = JSON.parse(await encryptionService.decrypt(cota.dadosCriptografados));
    return {
        id: cota.id,
        valor: cota.valor.toNumber(),
        createdAt: cota.createdAt,
        name: sensitiveData.name || null,
        cpf: sensitiveData.cpf || null,
        comprovante: sensitiveData.comprovante || null,
        observacoes: sensitiveData.observacoes || null,
    };
}


async function cotaRoutes(app: FastifyInstance) {
    app.withTypeProvider<ZodTypeProvider>().post('/', {
        onRequest: [app.authenticate],
        schema: {
            summary: 'Cria uma nova cota',
            tags: ['Cotas'],
            security: [{ bearerAuth: [] }],
            body: z.object({
                valor: z.number().positive(),
                name: z.string().optional(),
                cpf: z.string().optional(),
                comprovante: z.string().optional(),
                observacoes: z.string().optional(),
            }),
            response: { 201: z.object({
                message: z.string(),
                cota: z.object({ id: z.string(), valor: z.number() })
            })}
        }
    }, async (request, reply) => {
        const { valor, ...sensitiveData } = request.body;
        const userId = request.user.sub;

        const encryptedData = await encryptionService.encrypt(JSON.stringify(sensitiveData));

        const cota = await prisma.cota.create({
            data: { valor, dadosCriptografados: encryptedData, userId }
        });

        return reply.status(201).send({
            message: 'Cota created successfully',
            cota: { id: cota.id, valor: cota.valor.toNumber() }
        });
    });

    app.withTypeProvider<ZodTypeProvider>().get('/', {
        onRequest: [app.authenticate],
        schema: {
            summary: 'Lista as cotas do usuário',
            tags: ['Cotas'],
            security: [{ bearerAuth: [] }],
            response: { 200: z.array(decryptedCotaSchema) }
        }
    }, async (request, reply) => {
        const userId = request.user.sub;
        const cotas = await prisma.cota.findMany({
            where: { userId },
            orderBy: { createdAt: 'desc' }
        });

        const decryptedCotas = await Promise.all(cotas.map(formatCotaResponse));
        return reply.send(decryptedCotas);
    });
}

// =================================================================================
// 6. INICIALIZAÇÃO DO SERVIDOR
// =================================================================================

const main = async () => {
  const loggerOptions: LoggerOptions = {
    level: env.NODE_ENV === 'development' ? 'debug' : 'info',
  };

  if (env.NODE_ENV === 'development') {
    loggerOptions.transport = {
      target: 'pino-pretty',
    };
  }

  const app = fastify({
    logger: loggerOptions,
  }).withTypeProvider<ZodTypeProvider>();

  app.setErrorHandler(errorHandler);
  
  // --- Registro de Plugins ---
  await app.register(jwt, { secret: env.JWT_SECRET, sign: { expiresIn: '7d' } });
  await app.register(helmet, { contentSecurityPolicy: false });
  await app.register(cors, { origin: env.FRONTEND_URL, credentials: true });
  await app.register(rateLimit, { max: 100, timeWindow: '1 minute' });
  
  // --- Configuração do Swagger ---
  await app.register(swagger, {
    openapi: {
        info: {
            title: 'API de Cotas e Autenticação',
            description: 'Documentação da API para o sistema de gerenciamento de cotas.',
            version: '1.0.0'
        },
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            }
        }
    },
    transform: jsonSchemaTransform,
  });

  await app.register(swaggerUI, {
    routePrefix: '/docs',
  });


  // --- Decorators e Rotas ---
  app.decorate('authenticate', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      await request.jwtVerify();
    } catch (err) {
      throw new HttpError(401, 'Unauthorized. Token is invalid or missing.');
    }
  });

  await app.register(authRoutes, { prefix: '/api/auth' });
  await app.register(cotaRoutes, { prefix: '/api/cotas' });
  
  app.get('/api/health', async (request, reply) => {
    return { status: 'ok', database: 'connected' };
  });

  await prisma.$connect();
  app.log.info('✅ Database connection successful.');

  await app.listen({ port: env.PORT, host: '0.0.0.0' });

  // --- Lógica do Socket.IO com autenticação ---
  const io = new SocketIOServer(app.server, { cors: { origin: env.FRONTEND_URL } });
  
  io.use((socket: Socket, next) => {
      const token = socket.handshake.auth.token;
      if (!token) {
          return next(new Error('Authentication error: Token not provided.'));
      }
      app.jwt.verify(token, (err: Error | null, decoded: FastifyJWT['payload'] | undefined) => {
          if (err || !decoded) {
              return next(new Error('Authentication error: Invalid token.'));
          }
          (socket as AuthenticatedSocket).data.user = decoded;
          next();
      });
  });

  io.on('connection', (socket: Socket) => {
    const authSocket = socket as AuthenticatedSocket;
    app.log.info(`🔌 Socket client connected: ${authSocket.id} (User: ${authSocket.data.user.email})`);

    socket.on('disconnect', () => {
        app.log.info(`🔌 Socket client disconnected: ${authSocket.id}`);
    });
  });

  const close = async () => {
    await app.close();
    await prisma.$disconnect();
  };
  process.on('SIGINT', close);
  process.on('SIGTERM', close);
};

main().catch((err) => {
  console.error('❌ Failed to start server:', err);
  process.exit(1);
});
