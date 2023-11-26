// Intended to be used with Prisma ORM
// Server-side only

import bcrypt from "bcrypt";
import { generateToken } from "./jwtUtil.js";
import { isValidUrl } from "./utils.js";

export class PrismaAuth {
    constructor(prisma) {
        this.prisma = prisma;
    }

    async cleanupExpiredSessions() {
        const prisma = this.prisma;

        const expiredSessions = await prisma.session.findMany({
          where: {
            expiresAt: { lt: new Date() } // lt means 'less than'
          }
        });

        console.log(expiredSessions)
      
        if (expiredSessions.length > 0) {
          await prisma.session.deleteMany({
            where: {
              id: { in: expiredSessions.map(session => session.id) }
            }
          });
        }
      }
      

    /**
     * @typedef {Object} loginData
     * @property {string} token - The token of the session.
     * @property {session} session - The session object.
     * @property {user} user - The user object.
     */

    /**
     * A function to login a user.
     * @param {string} email
     * @param {string} plainTextPassword
     * @returns {Promise<loginData>} An object containing the token and the user.
     * @throws {Error} Throws an error if there is an error logging in the user.
     */
    async loginUser(email, plainTextPassword) {
        const prisma = this.prisma;     

        const userExists = await this._userExists(email);

        if (!userExists) {
            throw new Error("User does not exist");
        }

        const user = await prisma.user.findUnique({
            where: {
                email: email
            }
        });

        const isPasswordValid = await this._validatePassword(plainTextPassword, user.password);
        if(!isPasswordValid) {
            throw new Error("Invalid password")
        }

        const token = generateToken(user);
        const session = await this._createSession(user.id, token);
        return { token: token, session: session, user: user };
    }

    /**
     * A function to validate a password.
     * @param {string} plainTextPassword - The plain text password to validate.
     * @param {string} hashedPassword - The hashed password to validate against.
     * @returns {Promise<boolean>} True if the password is valid, false otherwise.
     * @throws {Error} Throws an error if there is an error validating the password.
     * @private 
     */
    async _validatePassword(plainTextPassword, hashedPassword) {
        try {
            return await bcrypt.compare(plainTextPassword, hashedPassword);
        } catch (err) {
            throw new Error("Password verification failed");
        }
    }
        

    // Below this line is the main REGISTRATION logic. Above this line is LOGIN logic and helper functions.
    
    /**
     * @typedef {Object} session
     * @property {number} id - The id of the session.
     * @property {string} token - The token of the session.
     * @property {Date} createdAt - The date the session was created.
     * @property {Date} expiresAt - The date the session expires.
     * @property {boolean} invalidated - Whether the session is invalidated or not.
     * @property {User} user - The user object.
     */

    /**
     * @typedef {Object} sessionData
     * @property {string} token - The token of the session.
     * @property {session} session - The session object.
     */

    /**
     * @typedef {Object} user
     * @property {number} id - The id of the user.
     * @property {string} email - The email of the user.
     * @property {string} hashedPassword - The password of the user.
     * @property {string} name - The name of the user.
     */

    /**
     * A function to register a user.
     * @param {string} email
     * @param {string} plainTextPassword
     * @param {string} name
     * @returns {Promise<sessionData>} An object containing the token and the session.
     */
    async registerUser(email, plainTextPassword, name) {
        const prisma = this.prisma;

        if (!isValidUrl(email)) {
            throw new Error("Invalid email");
        }

        const passwordStrength = this._passwordStrengthChecker(plainTextPassword);
        if (passwordStrength !== "Password is strong") {
            throw new Error(passwordStrength);
        }

        const userExists = await this._userExists(email);
        if (userExists) {
            throw new Error("User already exists");
        }

        const hashedPassword = await this._hashPassword(plainTextPassword);
        const user = await this._createUser(email, hashedPassword, name);

        const token = generateToken(user);
        const session = await this._createSession(user.id, token);
        return { token: token, session: session };
    }

    /**
     * A function to check if a user exists. Uses email to determine if a user exists.
     * @param {string} email - The email address of the user.
     * @returns {Promise<boolean>} True if the user exists, false otherwise.
     */
    async _userExists(email) {
        // for QOL purposes and to make the code more readable
        const prisma = this.prisma;
        
        const user = await prisma.user.findUnique({
            where: {
                email: email,
            },
        });
        return user !== null;
    }

    /**
     * A function to create a session.
     * @param {number} userId - The id of the user.
     * @param {string} token - The token of the user.
     * @param {number} expiration - The expiration of the session. Defaults to 1 hour.
     * @returns {Promise<session>} The session object.
     */
    async _createSession(userId, token, expiration = 3600000) {
        const prisma = this.prisma;

        const session = await prisma.session.create({
            data: {
                jwtToken: token,
                createdAt: new Date(), // Default to current date
                expiresAt: new Date(Date.now() + expiration), // Default 1 hour
                invalidated: false,
                user: {
                    connect: { id: userId } // Correct way to link the session to the user
                }
            },
            include: {
                user: true
            }
        });
        return session;
    }

    /**
     * A function to create a user.
     * @param {string} email - The email address of the user.
     * @param {string} hashedPassword - The hashed password of the user.
     * @param {string} name - The name of the user.
     * @returns {Promise<user>} The user object.
     */
    async _createUser(email, hashedPassword, name) {
        const prisma = this.prisma;

        const user = await prisma.user.create({
            data: {
                email: email,
                password: hashedPassword,
                name: name,
            },
        });
        return user;
    }
    
    /**
     * Hashes a plain text password.
     * @param {string} plainTextPassword - The plain text password to hash.
     * @returns {Promise<string>} - The hashed password.
     * @throws {Error} Throws an error if there is an error hashing the password.
     * @private
     */
    async _hashPassword(plainTextPassword) {
        const saltRounds = 10;
        try {
            const hashedPassword = await bcrypt.hash(plainTextPassword, saltRounds);
            return hashedPassword;
        } catch (err) {
            throw new Error("Error hashing password");
        }
    }

    /**
     * A function to check if a password is strong enough. A password is considered strong if it is between 6 and 24 characters long. 
     * @param {string} password - The password to check.
     * @returns {string} A string indicating whether the password is strong or not.
     */
    _passwordStrengthChecker(password) {
        const MIN_PASSWORD_LENGTH = 6;
        const MAX_PASSWORD_LENGTH = 24;

        if (password.length < MIN_PASSWORD_LENGTH) {
            return "Password is too short";
        } else if ( password.length > MAX_PASSWORD_LENGTH) {
            return "Password is too long";
        }
        return "Password is strong";
    }

    createSessionCookie(session) {
        return `session=${session.jwtToken}; HttpOnly; Max-Age=${session.expiresAt.getTime() - Date.now()}`;
    }
}