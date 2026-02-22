CREATE TABLE IF NOT EXISTS admin_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'admin',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  price REAL NOT NULL DEFAULT 0,
  category TEXT NOT NULL DEFAULT 'General',
  description TEXT DEFAULT '',
  image_url TEXT DEFAULT '',
  image_urls TEXT DEFAULT '[]',
  stock INTEGER NOT NULL DEFAULT 0,
  featured INTEGER NOT NULL DEFAULT 0,
  sold_out INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO products (id, name, price, category, description, featured) VALUES
(1, 'Urban Shadow Hoodie', 89.99, 'Hoodies', 'Hoodie premium con capucha oversized y bordado exclusivo Bichi Archive.', 1),
(2, 'Street Core Tee', 45.99, 'T-shirts', 'Camiseta de algodon premium con estampado frontal Bichi Archive.', 1),
(3, 'Tactical Cargo Pants', 79.99, 'Cargo Pants', 'Pantalon cargo con multiples bolsillos y corte streetwear.', 0),
(4, 'Archive Snapback Cap', 34.99, 'Caps', 'Gorra snapback con logo bordado Bichi Archive.', 0),
(5, 'Night Ops Jacket', 129.99, 'Jackets', 'Chaqueta tecnica con detalles reflectantes y cierre YKK.', 1),
(6, 'Phantom Oversized Tee', 49.99, 'T-shirts', 'Camiseta oversized con grafico posterior exclusivo.', 0);
