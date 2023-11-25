const { prisma } = require('../src/prisma');

async function main() {
    const allUsers = await prisma.user.findMany();
    console.log(allUsers);
}