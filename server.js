// server.js
// Minimal Express API with IP whitelist middleware (single file)

const express = require("express");

const app = express();

// If your app is behind a proxy/load balancer (Heroku, Nginx, Cloudflare, etc.),
// enable this so req.ip respects X-Forwarded-For.
app.set("trust proxy", true);

// ---- 1) Configure your whitelist (exact IP matches) ----
// Add plain IPv4 (e.g., "203.0.113.42"), IPv6 (e.g., "2001:db8::1"),
// and localhost variants for local testing.
const WHITELIST = new Set([
  "127.0.0.1", // IPv4 localhost
  "::1", // IPv6 localhost
  "::ffff:127.0.0.1", // IPv6-mapped IPv4 localhost
  // '203.0.113.42',    // <- add real IPs here
  // '2001:db8::1',
]);

// ---- 2) Helper: normalize common IP formats ----
function normalizeIp(ip) {
  if (!ip) return "";
  // Strip IPv6 prefix for IPv4-mapped addresses, e.g., "::ffff:203.0.113.42"
  if (ip.startsWith("::ffff:")) return ip.replace("::ffff:", "");
  // Some environments might give "::ffff:127.0.0.1" already normalized via req.ip,
  // but we'll keep this for safety.
  return ip;
}

// ---- 3) IP whitelist middleware ----
function ipWhitelist(whitelistSet) {
  return function (req, res, next) {
    // req.ip is a single resolved IP. If trust proxy is true and X-Forwarded-For exists,
    // Express will pick the left-most entry as the client's IP.
    const rawIp = req.ip;
    const ip = normalizeIp(rawIp);

    if (whitelistSet.has(ip)) return next();

    // Optionally, you could also check req.ips (the full chain) if you want:
    // const anyForwardedAllowed = (req.ips || []).map(normalizeIp).some(ip => whitelistSet.has(ip));
    // if (anyForwardedAllowed) return next();

    return res.status(403).json({
      error: "Forbidden: IP not allowed",
      ip: ip || rawIp || null,
      allowed: false,
    });
  };
}

// ---- 4) Apply middleware to protected routes ----
// You can protect all routes:
app.use(ipWhitelist(WHITELIST));

// Or protect only a sub-path like '/api':
// app.use('/api', ipWhitelist(WHITELIST));

// ---- 5) Example routes ----
app.get("/", (req, res) => {
  res.json({ message: "Welcome! Your IP passed the whitelist check." });
});

app.get("/api/hello", (req, res) => {
    console.log("Request IP : ", req.ip)
  res.json({ message: "Hello from a protected API route." });
});

// ---- 6) Error handler (optional, for unexpected errors) ----
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Server error" });
});

// ---- 7) Start server ----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server listening on http://localhost:${PORT}`);
});
