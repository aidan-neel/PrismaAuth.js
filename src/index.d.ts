declare module '@aaidan5899/prisma-auth' {
    import { PrismaClient, Session, User } from "@prisma/client"; // Import Prisma types as needed
    export declare namespace PrismaAuthTypes {
    type SessionData = {
        token: string;
        session: Session;
    };

    type UserData = {
        id: number;
        email: string;
        hashedPassword: string;
        name: string;
    };

    type LoginData = {
        token: string;
        session: Session;
        user: UserData;
    };
    }

    export declare class PrismaAuth {
    constructor(prisma: PrismaClient);

    cleanupExpiredSessions(): Promise<void>;

    loginUser(email: string, plainTextPassword: string): Promise<PrismaAuthTypes.LoginData>;

    validatePassword(plainTextPassword: string, hashedPassword: string): Promise<boolean>;

    registerUser(email: string, plainTextPassword: string, name: string): Promise<PrismaAuthTypes.SessionData>;

    userExists(email: string): Promise<boolean>;

    createSession(userId: number, token: string, expiration?: number): Promise<Session>;

    createUser(email: string, hashedPassword: string, name: string): Promise<User>;

    hashPassword(plainTextPassword: string): Promise<string>;

    passwordStrengthChecker(password: string): string;

    createSessionCookie(session: Session): string;
    }
}