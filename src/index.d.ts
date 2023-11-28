
declare module '@aaidan5899/prisma-auth' {
  import { PrismaClient, Session, User } from '@prisma/client'; // Assuming PrismaClient, User, Session types are imported from '@prisma/client'
  import { EventEmitter } from 'events';
  
  export class PrismaAuth extends EventEmitter {
      currentUser: User | null;
  
      constructor(prisma: PrismaClient);
  
      validateSession(sessionToken: string): Promise<boolean>;
  
      signUserOut(sessionToken: string): Promise<boolean>;
  
      getSessionData(sessionToken: string): Promise<Session | null>;
  
      cleanupExpiredSessions(): Promise<void>;
  
      loginUser(email: string, plainTextPassword: string): Promise<LoginData>;
  
      validatePassword(plainTextPassword: string, hashedPassword: string): Promise<boolean>;
  
      registerUser(email: string, plainTextPassword: string, name: string): Promise<SessionData>;
  
      userExists(email: string): Promise<boolean>;
  
      createSession(userId: number, token: string, expiration?: number): Promise<Session>;
  
      createUser(email: string, hashedPassword: string, name: string): Promise<User>;
  
      hashPassword(plainTextPassword: string): Promise<string>;
  
      passwordStrengthChecker(password: string): string;
  
      createSessionCookie(session: Session): string;
  }
  
  export interface LoginData {
      token: string;
      session: Session;
      user: User;
  }
  
  export interface SessionData {
      token: string;
      session: Session;
      user: User;
  }
  
  export interface Session {
      id: number;
      jwtToken: string;
      createdAt: Date;
      expiresAt: Date;
      invalidated: boolean;
      user: User;
  }
  
  export interface User {
      id: number;
      email: string;
      password: string;
      name: string;
  }
  
}
