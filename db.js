import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = process.env.SQLITE_PATH || path.join(__dirname, "data", "app.sqlite");
const resolvedDbPath = path.resolve(process.cwd(), dbPath);
const dbDir = path.dirname(resolvedDbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new Database(resolvedDbPath);
db.pragma("journal_mode = WAL");

const schemaPath = path.join(__dirname, "db", "sqlite", "schema.sql");
const schema = fs.readFileSync(schemaPath, "utf8");
db.exec(schema);

const columns = db.prepare("PRAGMA table_info(products)").all();
const hasImageUrls = columns.some((col) => col.name === "image_urls");
if (!hasImageUrls) {
  db.prepare("ALTER TABLE products ADD COLUMN image_urls TEXT DEFAULT '[]'").run();
}

db.prepare(
  `CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`
).run();

db.prepare(
  `CREATE TABLE IF NOT EXISTS sizes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`
).run();

db.prepare(
  `CREATE TABLE IF NOT EXISTS product_sizes (
    product_id INTEGER NOT NULL,
    size_id INTEGER NOT NULL,
    PRIMARY KEY (product_id, size_id),
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
    FOREIGN KEY (size_id) REFERENCES sizes(id) ON DELETE CASCADE
  )`
).run();


const rows = db.prepare("SELECT id, image_url, image_urls FROM products").all();
const update = db.prepare("UPDATE products SET image_urls = ? WHERE id = ?");
for (const row of rows) {
  const current = String(row.image_urls || "");
  const hasList = current.trim().startsWith("[") && current.trim().length > 2;
  if (!hasList && row.image_url) {
    update.run(JSON.stringify([row.image_url]), row.id);
  }
}

export default db;
