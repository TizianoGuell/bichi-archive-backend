import "dotenv/config";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import multer from "multer";
import db from "./db.js";
import { clearAuthCookie, requireAdmin, setAuthCookie, signAdminToken, parseAdminToken } from "./auth.js";

const app = express();
const port = Number(process.env.PORT || process.env.API_PORT || 4000);
app.set("trust proxy", 1);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uploadDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadDir, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadDir),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname || "").toLowerCase();
      cb(null, `${crypto.randomUUID()}${ext}`);
    },
  }),
  fileFilter: (_req, file, cb) => {
    cb(null, Boolean(file.mimetype && file.mimetype.startsWith("image/")));
  },
  limits: { fileSize: 5 * 1024 * 1024 },
});

async function bootstrapAdminFromEnv() {
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;

  if (!email || !password) return;

  const hash = await bcrypt.hash(password, 10);
  const existing = db
    .prepare("SELECT id FROM admin_users WHERE email = ? LIMIT 1")
    .get(email);

  if (existing) {
    db.prepare("UPDATE admin_users SET password_hash = ?, role = 'admin' WHERE id = ?").run(
      hash,
      existing.id
    );
    // eslint-disable-next-line no-console
    console.log(`Bootstrap admin updated: ${email}`);
    return;
  }

  db.prepare("INSERT INTO admin_users (email, password_hash, role) VALUES (?, ?, 'admin')").run(
    email,
    hash
  );
  // eslint-disable-next-line no-console
  console.log(`Bootstrap admin created: ${email}`);
}

function toImageUrls(row) {
  const raw = row?.image_urls;
  if (Array.isArray(raw)) return raw.filter((url) => typeof url === "string" && url.trim().length > 0);
  if (typeof raw === "string" && raw.trim()) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return parsed.filter((url) => typeof url === "string" && url.trim().length > 0);
      }
    } catch {
      // ignore invalid JSON
    }
  }
  const fallback = row?.image_url;
  return fallback ? [String(fallback)] : [];
}

function normalizeProduct(row) {
  if (!row) return row;
  const image_urls = toImageUrls(row);
  return {
    ...row,
    image_urls,
    image_url: row.image_url || image_urls[0] || "",
    featured: Boolean(row.featured),
    sold_out: Boolean(row.sold_out),
  };
}

app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "http://localhost:8080",
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());
app.use("/uploads", express.static(uploadDir));

app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/api/products", (_req, res) => {
  try {
    const rows = db
      .prepare(
        `SELECT id, name, price, category, description, image_url, image_urls, stock, featured, sold_out, created_at
         FROM products
         ORDER BY featured DESC, created_at DESC`
      )
      .all();
    res.json(rows.map(normalizeProduct));
  } catch {
    res.status(500).json({ error: "Failed to load products" });
  }
});

app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const admin = db
      .prepare("SELECT id, email, password_hash, role FROM admin_users WHERE email = ? LIMIT 1")
      .get(email);

    if (!admin) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, admin.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = signAdminToken({ sub: admin.id, email: admin.email, role: admin.role });
    setAuthCookie(res, token);
    return res.json({ user: { id: admin.id, email: admin.email, role: admin.role } });
  } catch {
    return res.status(500).json({ error: "Login failed" });
  }
});

app.post("/api/admin/logout", (_req, res) => {
  clearAuthCookie(res);
  res.status(204).send();
});

app.post("/api/admin/upload", requireAdmin, upload.single("image"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No image file provided" });
  }
  const baseUrl = process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get("host")}`;
  return res.json({ url: `${baseUrl}/uploads/${req.file.filename}` });
});

app.get("/api/admin/tags", requireAdmin, (_req, res) => {
  try {
    const rows = db.prepare("SELECT id, name, created_at FROM tags ORDER BY name ASC").all();
    return res.json(rows);
  } catch {
    return res.status(500).json({ error: "Failed to load tags" });
  }
});

app.post("/api/admin/tags", requireAdmin, (req, res) => {
  const name = String(req.body?.name || "").trim();
  if (!name) return res.status(400).json({ error: "name is required" });

  try {
    const result = db.prepare("INSERT INTO tags (name) VALUES (?)").run(name);
    const row = db.prepare("SELECT id, name, created_at FROM tags WHERE id = ?").get(result.lastInsertRowid);
    return res.status(201).json(row);
  } catch (err) {
    if (String(err?.message || "").includes("UNIQUE")) {
      return res.status(409).json({ error: "Tag already exists" });
    }
    return res.status(500).json({ error: "Failed to create tag" });
  }
});

app.put("/api/admin/tags/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const name = String(req.body?.name || "").trim();
  if (!name) return res.status(400).json({ error: "name is required" });

  try {
    db.prepare("UPDATE tags SET name = ? WHERE id = ?").run(name, id);
    const row = db.prepare("SELECT id, name, created_at FROM tags WHERE id = ?").get(id);
    return res.json(row || null);
  } catch (err) {
    if (String(err?.message || "").includes("UNIQUE")) {
      return res.status(409).json({ error: "Tag already exists" });
    }
    return res.status(500).json({ error: "Failed to update tag" });
  }
});

app.delete("/api/admin/tags/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  try {
    db.prepare("DELETE FROM tags WHERE id = ?").run(id);
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: "Failed to delete tag" });
  }
});

app.get("/api/admin/session", (req, res) => {
  const token = parseAdminToken(req);
  if (!token) {
    return res.json({ user: null });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (payload?.role !== "admin") {
      return res.json({ user: null });
    }
    return res.json({
      user: { id: Number(payload.sub), email: payload.email, role: payload.role },
      isAdmin: true,
    });
  } catch {
    return res.json({ user: null });
  }
});

app.get("/api/admin/products", requireAdmin, (_req, res) => {
  try {
    const rows = db.prepare("SELECT * FROM products ORDER BY created_at DESC").all();
    return res.json(rows.map(normalizeProduct));
  } catch {
    return res.status(500).json({ error: "Failed to load admin products" });
  }
});

app.get("/api/admin/debug/db", requireAdmin, (_req, res) => {
  try {
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
      .all();
    const productsCount = db.prepare("SELECT COUNT(*) as count FROM products").get();
    const adminsCount = db.prepare("SELECT COUNT(*) as count FROM admin_users").get();

    return res.json({
      sqlitePath: process.env.SQLITE_PATH || "data/app.sqlite",
      tables,
      counts: {
        products: Number(productsCount?.count || 0),
        admins: Number(adminsCount?.count || 0),
      },
    });
  } catch {
    return res.status(500).json({ error: "Failed to read debug db info" });
  }
});

app.get("/api/admin/debug/products", requireAdmin, (_req, res) => {
  try {
    const rows = db
      .prepare(
        `SELECT id, name, price, category, stock, featured, sold_out, created_at
         FROM products
         ORDER BY created_at DESC
         LIMIT 50`
      )
      .all();
    return res.json(rows.map(normalizeProduct));
  } catch {
    return res.status(500).json({ error: "Failed to read debug products" });
  }
});

app.post("/api/admin/products", requireAdmin, (req, res) => {
  const { name, price, category, description, image_url, image_urls, stock, featured, sold_out } = req.body ?? {};
  if (!name || !category) {
    return res.status(400).json({ error: "name and category are required" });
  }
  const urls = Array.isArray(image_urls) ? image_urls.filter((url) => typeof url === "string" && url.trim()) : [];
  const primaryUrl = urls[0] || image_url || "";

  try {
    const result = db
      .prepare(
        `INSERT INTO products (name, price, category, description, image_url, image_urls, stock, featured, sold_out)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        name,
        Number(price || 0),
        category,
        description || "",
        primaryUrl,
        JSON.stringify(urls.length ? urls : primaryUrl ? [primaryUrl] : []),
        Number(stock || 0),
        featured ? 1 : 0,
        sold_out ? 1 : 0
      );

    const row = db.prepare("SELECT * FROM products WHERE id = ?").get(result.lastInsertRowid);
    return res.status(201).json(normalizeProduct(row));
  } catch {
    return res.status(500).json({ error: "Failed to create product" });
  }
});

app.put("/api/admin/products/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { name, price, category, description, image_url, image_urls, stock, featured, sold_out } = req.body ?? {};
  const urls = Array.isArray(image_urls) ? image_urls.filter((url) => typeof url === "string" && url.trim()) : [];
  const primaryUrl = urls[0] || image_url || "";

  try {
    db.prepare(
      `UPDATE products
       SET name = ?, price = ?, category = ?, description = ?, image_url = ?, image_urls = ?, stock = ?, featured = ?, sold_out = ?,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`
    ).run(
      name,
      Number(price || 0),
      category,
      description || "",
      primaryUrl,
      JSON.stringify(urls.length ? urls : primaryUrl ? [primaryUrl] : []),
      Number(stock || 0),
      featured ? 1 : 0,
      sold_out ? 1 : 0,
      id
    );

    const row = db.prepare("SELECT * FROM products WHERE id = ?").get(id);
    return res.json(normalizeProduct(row || null));
  } catch {
    return res.status(500).json({ error: "Failed to update product" });
  }
});

app.delete("/api/admin/products/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  try {
    db.prepare("DELETE FROM products WHERE id = ?").run(id);
    return res.status(204).send();
  } catch {
    return res.status(500).json({ error: "Failed to delete product" });
  }
});

async function startServer() {
  await bootstrapAdminFromEnv();
  app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`API running on http://localhost:${port}`);
  });
}

startServer();
