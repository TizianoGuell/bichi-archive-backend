import jwt from "jsonwebtoken";

const COOKIE_NAME = "admin_token";

export function signAdminToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" });
}

export function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

export function clearAuthCookie(res) {
  res.clearCookie(COOKIE_NAME);
}

export function parseAdminToken(req) {
  const bearer = req.headers.authorization?.startsWith("Bearer ")
    ? req.headers.authorization.slice(7)
    : null;
  return req.cookies[COOKIE_NAME] || bearer || null;
}

export function requireAdmin(req, res, next) {
  const token = parseAdminToken(req);
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (payload?.role !== "admin") {
      return res.status(403).json({ error: "Forbidden" });
    }
    req.admin = payload;
    return next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}
