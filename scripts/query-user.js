const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function main() {
  const user = await prisma.user.findFirst({
    select: {
      id: true,
      email: true,
      name: true,
      isAdmin: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  if (!user) {
    console.log('Nenhum usuário encontrado');
    return;
  }

  console.log(user);
}

main()
  .catch((error) => {
    console.error('Erro ao consultar usuário:', error?.message || error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });


