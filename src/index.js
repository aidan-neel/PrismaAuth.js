import { prisma } from '../src/prisma.js'; // Adjust the path as per your directory structure

async function main() {
  const allUsers = await prisma.user.findMany();
  console.log(allUsers);
}

main();
