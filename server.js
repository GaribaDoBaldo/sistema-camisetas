const fs = require("fs");
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
    },
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));


app.get("/setup-admin", async (req, res) => {
  try {
    const result = await pool.query("SELECT COUNT(*)::int AS count FROM users WHERE role = 'admin'");
    const adminCount = result.rows[0].count;

    if (adminCount > 0) {
      return res.status(403).send("❌ Já existe um ADMIN criado. (Remova a rota /setup-admin por segurança)");
    }

    res.send(`
      <h2>Criar Admin</h2>
      <form method="POST" action="/setup-admin">
        <div>
          <label>Nome:</label><br/>
          <input name="name" required />
        </div>
        <br/>
        <div>
          <label>Email:</label><br/>
          <input name="email" type="email" required />
        </div>
        <br/>
        <div>
          <label>Senha:</label><br/>
          <input name="password" type="password" required />
        </div>
        <br/>
        <button type="submit">Criar Admin</button>
      </form>
    `);
  } catch (err) {
    console.error(err);
    res.status(500).send("❌ Erro: " + err.message);
  }
});

app.post("/setup-admin", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // segurança: não deixa criar admin se já existir
    const result = await pool.query("SELECT COUNT(*)::int AS count FROM users WHERE role = 'admin'");
    const adminCount = result.rows[0].count;
    if (adminCount > 0) {
      return res.status(403).send("❌ Já existe um ADMIN criado.");
    }

    const password_hash = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, 'admin')",
      [name, email, password_hash]
    );

    res.send("✅ Admin criado com sucesso! Agora vamos criar a tela de login. (Depois remova /setup-admin)");
  } catch (err) {
    console.error(err);
    res.status(500).send("❌ Erro: " + err.message);
  }
});
app.get("/", (req, res) => {
  res.send("Sistema rodando 🚀");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Servidor rodando na porta", PORT);
});
