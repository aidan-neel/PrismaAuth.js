import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function findUsersByEmail(email) {
  try {
    const users = await prisma.user.findMany({
      where: {
        email: email,
      },
    });
    return users;
  } catch (error) {
    console.error('Error fetching users:', error);
    throw error;
  }
}

export { prisma };
