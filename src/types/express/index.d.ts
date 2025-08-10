import { JWTPayload } from './jwtTypes'; // ajuste o caminho para seu tipo real

declare global {
  namespace Express {
    interface Request {
      user?: JWTPayload & {
        id: string;
        email: string;
        userId?: number; // se realmente precisar
      };
    }
  }
}
