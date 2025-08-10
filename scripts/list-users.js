const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function main() {
  const users = await prisma.user.findMany({
    select: {
      id: true,
      email: true,
      name: true,
      isAdmin: true,
      createdAt: true,
      updatedAt: true,
    },
    orderBy: { createdAt: 'asc' },
  });

  if (!users || users.length === 0) {
    console.log('Nenhum usuário encontrado');
    return;
  }

  console.log(JSON.stringify(users, null, 2));
}

main()
  .catch((error) => {
    console.error('Erro ao listar usuários:', error?.message || error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });


