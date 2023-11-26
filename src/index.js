import { prisma } from './prisma.js'; // Adjust the path as per your directory structure
import { PrismaAuth } from './prismaAuth.js';

async function main() {
  const prismaAuth = new PrismaAuth(prisma);

  prismaAuth.cleanupExpiredSessions();

/*try {
    console.log("Logging in...")

    const { token: token2, session: session2 } = await prismaAuth.loginUser(
      'test6@gmail.com',
      'password'
    )

    console.log(token2);
    console.log(session2);
    console.log(session2.user);
  } catch(err) {
    console.log(err);
  } */
}

main();
