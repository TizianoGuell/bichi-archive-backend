import "dotenv/config";
import bcrypt from "bcryptjs";
import db from "./db.js";

const email = process.env.ADMIN_EMAIL;
const password = process.env.ADMIN_PASSWORD;

if (!email || !password) {
  // eslint-disable-next-line no-console
  console.error("Set ADMIN_EMAIL and ADMIN_PASSWORD in environment");
  process.exit(1);
}

const existing = db.prepare("SELECT id FROM admin_users WHERE email = ? LIMIT 1").get(email);
if (existing) {
  // eslint-disable-next-line no-console
  console.error(`Admin already exists for ${email}`);
  process.exit(1);
}

const hash = await bcrypt.hash(password, 10);
db.prepare("INSERT INTO admin_users (email, password_hash, role) VALUES (?, ?, 'admin')").run(email, hash);

// eslint-disable-next-line no-console
console.log(`Admin created: ${email}`);
