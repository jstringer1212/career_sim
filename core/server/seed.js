const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
  // Seed Users
  const user1 = await prisma.user.create({
    data: { name: 'Alice' },
  });

  const user2 = await prisma.user.create({
    data: { name: 'Bob' },
  });

  // Seed Products
  const product1 = await prisma.product.create({
    data: { name: 'Laptop', price: 999.99 },
  });

  const product2 = await prisma.product.create({
    data: { name: 'Smartphone', price: 799.99 },
  });

  // Seed Reviews
  await prisma.review.create({
    data: {
      content: 'Fantastic performance and build quality!',
      userId: user1.id,
      productId: product1.id,
    },
  });

  await prisma.review.create({
    data: {
      content: 'Decent phone for the price.',
      userId: user2.id,
      productId: product2.id,
    },
  });

  console.log('Seeding completed!');
}

main()
  .catch((e) => {
    console.error('Error during seeding:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
