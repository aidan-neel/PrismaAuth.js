declare module '@aaidan5899/prisma-auth' {
    import { PrismaClient } from '@prisma/client';
    export class PrismaAuth {
        constructor(prisma: PrismaClient);

        cleanupExpiredSessions(): Promise<void>;

        loginUser(email: string, plainTextPassword: string): Promise<LoginData>;

        registerUser(email: string, plainTextPassword: string, name: string): Promise<SessionData>;

        createSessionCookie(session: Session): string;
    }

    // Define additional types as used in your class
    export interface LoginData {
        token: string;
        session: Session;
        user: User;
    }

    export interface SessionData {
        token: string;
        session: Session;
    }

    export interface Session {
        id: number;
        token: string;
        createdAt: Date;
        expiresAt: Date;
        invalidated: boolean;
        user: User;
    }

    export interface User {
        id: number;
        email: string;
        hashedPassword: string;
        name: string;
    }
}