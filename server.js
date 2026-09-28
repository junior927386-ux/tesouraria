require("dotenv").config();
const express = require("express"), session = require("express-session"), 
  bcrypt = require("bcryptjs"), passport = require("passport"), GoogleStrategy = require("passport-google-oauth20").Strategy,
  path = require("path"), crypto = require("crypto"), os = require("os");

let DatabaseSync;
try { ({ DatabaseSync } = require("node:sqlite")); }
catch { console.error("Este app precisa do Node.js 22.13 ou mais novo. Instale o LTS em https://nodejs.org"); process.exit(1); }

const VERSION = "1.8";
const PORT = +process.env.PORT || 8000;
const SESSION_MAX_AGE = 30 * 24 * 60 * 60 * 1000; // 30 dias (app: não pedir login toda hora)
const googleOn = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
const ROLES = ["Presidente","Vice-presidente","Secretário-geral","1° secretário","Tesoureiro-geral","1° tesoureiro","Dir. Social","V. Dir. Social","Dir. De imprensa","V. Dir. Imprensa","Dir. De esportes","V. Dir. Esportes","Dir. De cultura","V. Dir. Cultural","Dir. De saúde e meio ambiente","V. Dir. De saúde e meio ambiente","Dir. Da mulher","V. Dir. Da mulher","Dir. De proteção a diversidade","V. Dir. De proteção à diversidade"];

const db = new DatabaseSync(process.env.DB_PATH || path.join(__dirname, "caixa-azul.db"));
db.exec("PRAGMA foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT,name TEXT NOT NULL,google_id TEXT UNIQUE,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS movements(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,type TEXT NOT NULL,description TEXT NOT NULL,amount REAL NOT NULL,category TEXT NOT NULL,date TEXT NOT NULL,requester_name TEXT,requester_role TEXT,receipt_code TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id));
CREATE INDEX IF NOT EXISTS idx_mov_user ON movements(user_id,date);
`);

db.exec("CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)");
function sessionSecret() {
  const env = process.env.SESSION_SECRET;
  if (env && !env.startsWith("troque-")) return env;
  let r = db.prepare("SELECT value FROM settings WHERE key='session_secret'").get();
  if (!r) { r = { value: crypto.randomBytes(32).toString("hex") }; db.prepare("INSERT INTO settings(key,value) VALUES('session_secret',?)").run(r.value); }
  return r.value;
}

// Sessões em SQLite: continuam válidas depois de reiniciar o servidor
class SqliteStore extends session.Store {
  constructor() {
    super();
    db.exec("CREATE TABLE IF NOT EXISTS sessions(sid TEXT PRIMARY KEY,data TEXT NOT NULL,expires INTEGER NOT NULL)");
    const clean = () => db.prepare("DELETE FROM sessions WHERE expires<?").run(Date.now());
    clean(); setInterval(clean, 3600000).unref();
  }
  get(sid, cb) {
    try { const r = db.prepare("SELECT data,expires FROM sessions WHERE sid=?").get(sid); cb(null, r && r.expires > Date.now() ? JSON.parse(r.data) : null); }
    catch (e) { cb(e); }
  }
  set(sid, sess, cb) {
    try {
      const exp = sess.cookie && sess.cookie.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + SESSION_MAX_AGE;
      db.prepare("INSERT OR REPLACE INTO sessions(sid,data,expires) VALUES(?,?,?)").run(sid, JSON.stringify(sess), exp);
      cb && cb(null);
    } catch (e) { cb && cb(e); }
  }
  touch(sid, sess, cb) { this.set(sid, sess, cb); }
  destroy(sid, cb) {
    try { db.prepare("DELETE FROM sessions WHERE sid=?").run(sid); cb && cb(null); } catch (e) { cb && cb(e); }
  }
}

const app = express();
app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  store: new SqliteStore(),
  secret: sessionSecret(),
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: "auto", maxAge: SESSION_MAX_AGE }
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, "public")));

const normEmail = x => String(x || "").replace(/[\s\u200B-\u200D\u2060\uFEFF]/g, "").toLowerCase();
// Administradores: coluna nova, ADMIN_EMAILS no .env e, se ainda não houver admin, a conta mais antiga vira admin
if (!db.prepare("PRAGMA table_info(users)").all().some(c => c.name === "is_admin"))
  db.exec("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0");
for (const a of (process.env.ADMIN_EMAILS || "").split(",").map(normEmail).filter(Boolean))
  db.prepare("UPDATE users SET is_admin=1 WHERE email=?").run(a);
if (!db.prepare("SELECT id FROM users WHERE is_admin=1").get())
  db.prepare("UPDATE users SET is_admin=1 WHERE id=(SELECT MIN(id) FROM users)").run();
const noAdmin = () => !db.prepare("SELECT id FROM users WHERE is_admin=1").get();
const adminOnly = (q, s, n) => q.user && q.user.is_admin ? n() : s.status(403).json({ error: "Acesso restrito a administradores." });
const dropSessions = id => db.prepare("DELETE FROM sessions WHERE data LIKE ?").run(`%"passport":{"user":${Number(id)}}%`);
const auth = (q, s, n) => q.user ? n() : s.status(401).json({ error: "Não autenticado." });
const newCode = () => `REC-${new Date().getFullYear()}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
const publicUser = u => ({ id: u.id, email: u.email, name: u.name, is_admin: u.is_admin ? 1 : 0 });

// Limite simples de tentativas de login por IP
const fails = new Map();
const blocked = ip => { const f = fails.get(ip); return f && f.n >= 10 && Date.now() - f.t < 900000; };
const addFail = ip => { const f = fails.get(ip); fails.set(ip, { n: f && Date.now() - f.t < 900000 ? f.n + 1 : 1, t: Date.now() }); };

passport.serializeUser((u, d) => d(null, u.id));
passport.deserializeUser((id, d) => d(null, db.prepare("SELECT id,email,name,is_admin FROM users WHERE id=?").get(id) || false));

if (googleOn) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID, clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || `http://localhost:${PORT}/auth/google/callback`
  }, (_a, _b, profile, done) => {
    const e = normEmail(profile.emails && profile.emails[0] && profile.emails[0].value);
    if (!e) return done(null, false);
    let u = db.prepare("SELECT * FROM users WHERE email=?").get(e);
    if (!u) {
      const r = db.prepare("INSERT INTO users(email,name,google_id,is_admin) VALUES(?,?,?,?)").run(e, profile.displayName || e.split("@")[0], profile.id, noAdmin() ? 1 : 0);
      u = db.prepare("SELECT * FROM users WHERE id=?").get(r.lastInsertRowid);
    } else if (!u.google_id) {
      db.prepare("UPDATE users SET google_id=? WHERE id=?").run(profile.id, u.id);
    }
    done(null, u);
  }));
}

app.get("/api/config", (q, s) => s.json({ googleEnabled: googleOn, roles: ROLES, version: VERSION }));
app.get("/api/me", (q, s) => s.json({ user: q.user || null }));

app.post("/api/register", (q, s) => {
  const e = normEmail(q.body.email), n = String(q.body.name || "").trim(), p = String(q.body.password || "");
  if (!/^[^\s@]+@(gmail|googlemail)\.com$/.test(e)) return s.status(400).json({ error: `Use um endereço Gmail (@gmail.com). O servidor recebeu: "${e}"` });
  if (n.length < 2) return s.status(400).json({ error: "Informe seu nome." });
  if (p.length < 8) return s.status(400).json({ error: "A senha deve ter pelo menos 8 caracteres." });
  if (db.prepare("SELECT id FROM users WHERE email=?").get(e)) return s.status(409).json({ error: "Este Gmail já está cadastrado." });
  const r = db.prepare("INSERT INTO users(email,password_hash,name,is_admin) VALUES(?,?,?,?)").run(e, bcrypt.hashSync(p, 12), n, noAdmin() ? 1 : 0);
  const u = db.prepare("SELECT id,email,name,is_admin FROM users WHERE id=?").get(r.lastInsertRowid);
  q.login(u, err => err ? s.status(500).json({ error: "Erro ao iniciar sessão." }) : s.json({ user: publicUser(u) }));
});

app.post("/api/login", (q, s) => {
  if (blocked(q.ip)) return s.status(429).json({ error: "Muitas tentativas. Aguarde 15 minutos." });
  const u = db.prepare("SELECT * FROM users WHERE email=?").get(normEmail(q.body.email));
  if (!u || !u.password_hash || !bcrypt.compareSync(String(q.body.password || ""), u.password_hash)) {
    addFail(q.ip);
    return s.status(401).json({ error: "Gmail ou senha incorretos." });
  }
  fails.delete(q.ip);
  q.login(u, err => err ? s.status(500).json({ error: "Erro ao iniciar sessão." }) : s.json({ user: publicUser(u) }));
});

app.post("/api/logout", (q, s) => q.logout(() => s.json({ ok: true })));

app.get("/auth/google", (q, s, n) => googleOn ? passport.authenticate("google", { scope: ["profile", "email"] })(q, s, n) : s.redirect("/?google=disabled"));
app.get("/auth/google/callback", (q, s, n) => googleOn ? passport.authenticate("google", { failureRedirect: "/?google=failed" })(q, s, n) : s.redirect("/?google=disabled"), (q, s) => s.redirect("/"));

app.get("/api/movements", auth, (q, s) => s.json(db.prepare("SELECT * FROM movements WHERE user_id=? ORDER BY date DESC,id DESC").all(q.user.id)));

app.post("/api/movements", auth, (q, s) => {
  const b = q.body, type = b.type === "saida" ? "saida" : "entrada", desc = String(b.description || "").trim(),
    amount = Math.round(Number(b.amount) * 100) / 100, date = String(b.date || ""), cat = String(b.category || "Outros").slice(0, 40);
  let rn = null, rr = null;
  if (!desc || !Number.isFinite(amount) || amount <= 0 || !/^\d{4}-\d{2}-\d{2}$/.test(date) || isNaN(new Date(date + "T12:00:00")))
    return s.status(400).json({ error: "Preencha descrição, valor e data corretamente." });
  if (type === "saida") {
    rn = String(b.requesterName || "").trim(); rr = String(b.requesterRole || "");
    if (!rn || !ROLES.includes(rr)) return s.status(400).json({ error: "Informe nome e cargo válidos para a saída." });
  }
  const r = db.prepare("INSERT INTO movements(user_id,type,description,amount,category,date,requester_name,requester_role,receipt_code) VALUES(?,?,?,?,?,?,?,?,?)")
    .run(q.user.id, type, desc.slice(0, 200), amount, cat, date, rn, rr, type === "saida" ? newCode() : null);
  s.json(db.prepare("SELECT * FROM movements WHERE id=?").get(r.lastInsertRowid));
});

app.delete("/api/movements/:id", auth, (q, s) => {
  const r = db.prepare("DELETE FROM movements WHERE id=? AND user_id=?").run(q.params.id, q.user.id);
  s.json({ ok: !!r.changes });
});

app.get("/api/movements/:id/receipt", auth, (q, s) => {
  const m = q.user.is_admin ? db.prepare("SELECT * FROM movements WHERE id=?").get(q.params.id) : db.prepare("SELECT * FROM movements WHERE id=? AND user_id=?").get(q.params.id, q.user.id);
  if (!m || m.type !== "saida") return s.status(404).send("Recibo não encontrado.");
  const e = x => String(x == null ? "" : x).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[c]));
  const money = new Intl.NumberFormat("pt-BR", { style: "currency", currency: "BRL" }).format(m.amount);
  const date = m.date.split("-").reverse().join("/");
  s.type("html").send(`<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${e(m.receipt_code)}</title><style>body{font-family:Arial,sans-serif;max-width:760px;margin:30px auto;padding:20px}.box{border:1px solid #bbb;padding:30px;border-radius:12px}.row{display:flex;justify-content:space-between;gap:12px;padding:13px 0;border-bottom:1px solid #ddd}.v{font-weight:bold;text-align:right}button{margin-bottom:16px;padding:10px 14px}@media print{button{display:none}}</style></head><body><button onclick="print()">Imprimir / Salvar PDF</button><div class="box"><h1>RECIBO DE SAÍDA</h1><p><b>${e(m.receipt_code)}</b></p><div class="row"><span>Data</span><span class="v">${date}</span></div><div class="row"><span>Valor</span><span class="v">${money}</span></div><div class="row"><span>Descrição</span><span class="v">${e(m.description)}</span></div><div class="row"><span>Solicitante</span><span class="v">${e(m.requester_name)}</span></div><div class="row"><span>Diretoria / Cargo</span><span class="v">${e(m.requester_role)}</span></div><p style="margin-top:60px;text-align:center;border-top:1px solid;padding-top:8px">${e(m.requester_name)}<br>${e(m.requester_role)}</p></div></body></html>`);
});

// Painel do administrador
app.get("/api/admin/users", auth, adminOnly, (q, s) => s.json(db.prepare(`SELECT u.id,u.email,u.name,u.is_admin,u.created_at,COUNT(m.id) AS movements,
  ROUND(COALESCE(SUM(CASE m.type WHEN 'entrada' THEN m.amount WHEN 'saida' THEN -m.amount END),0),2) AS balance
  FROM users u LEFT JOIN movements m ON m.user_id=u.id GROUP BY u.id ORDER BY u.id`).all()));
app.get("/api/admin/movements", auth, adminOnly, (q, s) => s.json(db.prepare("SELECT * FROM movements WHERE user_id=? ORDER BY date DESC,id DESC").all(q.query.user_id)));
app.post("/api/admin/users/:id/admin", auth, adminOnly, (q, s) => {
  const id = Number(q.params.id), on = q.body.admin ? 1 : 0;
  if (!on && db.prepare("SELECT COUNT(*) AS n FROM users WHERE is_admin=1 AND id<>?").get(id).n === 0)
    return s.status(400).json({ error: "Precisa existir pelo menos um administrador." });
  s.json({ ok: !!db.prepare("UPDATE users SET is_admin=? WHERE id=?").run(on, id).changes });
});
app.post("/api/admin/users/:id/password", auth, adminOnly, (q, s) => {
  const p = String(q.body.password || "");
  if (p.length < 8) return s.status(400).json({ error: "A senha deve ter pelo menos 8 caracteres." });
  const r = db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(bcrypt.hashSync(p, 12), q.params.id);
  dropSessions(q.params.id); s.json({ ok: !!r.changes });
});
app.delete("/api/admin/users/:id", auth, adminOnly, (q, s) => {
  const id = Number(q.params.id);
  if (id === q.user.id) return s.status(400).json({ error: "Você não pode excluir a própria conta." });
  db.prepare("DELETE FROM movements WHERE user_id=?").run(id); dropSessions(id);
  s.json({ ok: !!db.prepare("DELETE FROM users WHERE id=?").run(id).changes });
});

// Fallback (compatível com Express 5, onde app.get("*") não funciona mais)
app.use((q, s) => {
  if (q.method !== "GET" || q.path.startsWith("/api/")) return s.status(404).json({ error: "Não encontrado." });
  s.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Tesouraria DHG v${VERSION} rodando: http://localhost:${PORT}`);
  Object.values(os.networkInterfaces()).flat().filter(i => i && (i.family === "IPv4" || i.family === 4) && !i.internal)
    .forEach(i => console.log(`Em outro aparelho (mesmo Wi-Fi): http://${i.address}:${PORT}`));
})
  .on("error", e => {
    console.error(e.code === "EADDRINUSE" ? `A porta ${PORT} já está em uso. Feche a janela antiga do Tesouraria DHG e tente de novo.` : e);
    process.exit(1);
  });
