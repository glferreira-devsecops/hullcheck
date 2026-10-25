import jwt from "jsonwebtoken";
export const check = (t: string) => jwt.verify(t, key, { algorithms: ["none"] });
