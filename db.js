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

export default db;
