export const user = (id: string) =>
  prisma.$queryRawUnsafe("SELECT * FROM users WHERE id = " + id);
