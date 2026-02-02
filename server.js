const bcrypt = require("bcryptjs");
const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const pool = require("./db");
const path = require("path");

const app = express();

// necessário no Render
app.set("trust proxy", 1);

// sessão usando Postgres ✅
app.use(
  session({
    store: new pgSession({
      pool,
      tableName: "session",
    }),
    secret: process.env.SESSION_SECRET || "segredo-local",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,
      sameSite: "lax",
      httpOnly: true,
    },
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
// middleware: usuário logado?
function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

// tela de login
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

// login (POST)
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // busca usuário no banco
    const result = await pool.query(
      "SELECT id, name, email, password_hash, role FROM users WHERE email = $1 LIMIT 1",
      [email]
    );

    if (result.rowCount === 0) {
      return res.status(401).render("login", { error: "Email ou senha inválidos." });
    }

    const user = result.rows[0];

    // compara senha
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).render("login", { error: "Email ou senha inválidos." });
    }

    // salva na sessão (logado)
    req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };

    // redireciona
    if (user.role === "admin") return res.redirect("/admin");
    return res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    return res.status(500).render("login", { error: "Erro interno. Tente novamente." });
  }
});

// logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

// área do funcionário (protegida)
app.get("/dashboard", requireAuth, (req, res) => {
  res.send(`Olá, ${req.session.user.name}! ✅ Você está logado. <a href="/logout">Sair</a>`);
});

// área do admin (protegida)
// área do admin (protegida)
app.get("/admin", requireAuth, (req, res) => {
  if (req.session.user.role !== "admin") return res.status(403).send("Acesso negado.");
  res.render("admin", { user: req.session.user });
});

// listar usuários
app.get("/admin/users", requireAuth, async (req, res) => {
  if (req.session.user.role !== "admin") return res.status(403).send("Acesso negado.");

  const result = await pool.query("SELECT id, name, email, role FROM users ORDER BY id ASC");
  res.render("admin_users", { users: result.rows });
});

// formulário novo usuário
app.get("/admin/users/new", requireAuth, (req, res) => {
  if (req.session.user.role !== "admin") return res.status(403).send("Acesso negado.");
  res.render("admin_user_new", { error: null });
});

// criar usuário (POST)
app.post("/admin/users", requireAuth, async (req, res) => {
  try {
    if (req.session.user.role !== "admin") return res.status(403).send("Acesso negado.");

    const { name, email, password, role } = req.body;

    // evita email repetido
    const exists = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (exists.rowCount > 0) {
      return res.status(400).render("admin_user_new", { error: "Esse email já está cadastrado." });
    }

    const password_hash = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4)",
      [name, email, password_hash, role || "employee"]
    );

    res.redirect("/admin/users");
  } catch (err) {
    console.error(err);
    res.status(500).render("admin_user_new", { error: "Erro ao criar usuário." });
  }
});

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Servidor rodando na porta", PORT);
});
