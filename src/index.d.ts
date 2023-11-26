import { PrismaClient } from '@prisma/client';
import { EventEmitter } from 'events';

declare module '@aaidan5899/prisma-auth' {

  // Define any custom types used in your class, like sessionData, loginData, etc.
  type session = {
    id: number;
    token: string;
    createdAt: Date;
    expiresAt: Date;
    invalidated: boolean;
    user: user;
  };

  type sessionData = {
    token: string;
    session: session;
    user: user;
  };

  type loginData = {
    token: string;
    session: session;
    user: user;
  };

  type user = {
    id: number;
    email: string;
    hashedPassword: string;
    name: string;
  };

  // Declare the PrismaAuth class
  export class PrismaAuth extends EventEmitter {
    currentUser: user | null;

    constructor(prisma: PrismaClient);

    validateSession(sessionToken: string): Promise<boolean>;
    getSessionData(sessionToken: string): Promise<session | null>;
    cleanupExpiredSessions(): Promise<void>;
    loginUser(email: string, plainTextPassword: string): Promise<loginData>;
    validatePassword(plainTextPassword: string, hashedPassword: string): Promise<boolean>;
    registerUser(email: string, plainTextPassword: string, name: string): Promise<sessionData>;
    userExists(email: string): Promise<boolean>;
    createSession(userId: number, token: string, expiration?: number): Promise<session>;
    createUser(email: string, hashedPassword: string, name: string): Promise<user>;
    hashPassword(plainTextPassword: string): Promise<string>;
    passwordStrengthChecker(password: string): string;
    createSessionCookie(session: session): string;
  }
}
