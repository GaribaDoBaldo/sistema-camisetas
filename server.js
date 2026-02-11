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
      secure: process.env.NODE_ENV === "production",
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
app.get("/", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  return res.redirect("/login");
});

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
  res.render("dashboard", { user: req.session.user });
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
// =========================
// ESTOQUE (ADMIN) - LISTA
// =========================
app.get("/admin/estoque", requireAuth, async (req, res) => {
  try {
    if (req.session.user.role !== "admin") return res.status(403).send("Acesso negado.");

    const productsResult = await pool.query(
      `SELECT id, name, category, active
       FROM products
       ORDER BY id DESC`
    );

    const variantsResult = await pool.query(
      `SELECT v.id, v.product_id, v.sku, v.color, v.size, v.price_cents, v.stock, v.min_stock, v.active,
              p.name AS product_name
       FROM product_variants v
       JOIN products p ON p.id = v.product_id
       ORDER BY v.id DESC`
    );

    res.render("admin_estoque_index", {
      user: req.session.user,
      products: productsResult.rows,
      variants: variantsResult.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Erro ao carregar estoque.");
  }
});

// =========================
// ESTOQUE (ADMIN) - NOVO PRODUTO (FORM)
// =========================
app.get("/admin/estoque/novo-produto", requireAuth, (req, res) => {
  if (req.session.user.role !== "admin") return res.status(403).send("Acesso negado.");
  res.render("admin_estoque_novo_produto", { user: req.session.user, error: null });
});

// =========================
// ESTOQUE (ADMIN) - CRIAR PRODUTO (POST)
// =========================
app.post("/admin/estoque/produto", requireAuth, async (req, res) => {
  try {
    if (req.session.user.role !== "admin") return res.status(403).send("Acesso negado.");

    const { name, category, description } = req.body;

    if (!name || name.trim().length < 2) {
      return res.status(400).render("admin_estoque_novo_produto", {
        user: req.session.user,
        error: "Nome do produto é obrigatório.",
      });
    }

    await pool.query(
      "INSERT INTO products (name, category, description) VALUES ($1, $2, $3)",
      [name.trim(), category?.trim() || null, description?.trim() || null]
    );

    res.redirect("/admin/estoque");
  } catch (err) {
    console.error(err);
    res.status(500).send("Erro ao criar produto.");
  }
});
// =========================
// ESTOQUE (ADMIN) - DETALHE DO PRODUTO + VARIAÇÕES
// =========================
app.get("/admin/estoque/produto/:id", requireAuth, async (req, res) => {
  try {
    if (req.session.user.role !== "admin") return res.status(403).send("Acesso negado.");

    const productId = req.params.id;

    const productResult = await pool.query("SELECT * FROM products WHERE id = $1", [productId]);
    if (productResult.rowCount === 0) return res.status(404).send("Produto não encontrado.");

    const variantsResult = await pool.query(
      `SELECT * FROM product_variants
       WHERE product_id = $1
       ORDER BY id DESC`,
      [productId]
    );

    res.render("admin_estoque_produto", {
      user: req.session.user,
      product: productResult.rows[0],
      variants: variantsResult.rows,
      error: null,
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Erro ao abrir produto.");
  }
});
// =========================
// ESTOQUE (ADMIN) - CRIAR VARIAÇÃO
// =========================
app.post("/admin/estoque/produto/:id/variacao", requireAuth, async (req, res) => {
  try {
    if (req.session.user.role !== "admin") return res.status(403).send("Acesso negado.");

    const productId = req.params.id;
    const { sku, color, size, price_cents, stock, min_stock } = req.body;

    await pool.query(
      `INSERT INTO product_variants (product_id, sku, color, size, price_cents, stock, min_stock)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        productId,
        sku?.trim() || null,
        color?.trim() || null,
        size?.trim() || null,
        Number(price_cents || 0),
        Number(stock || 0),
        Number(min_stock || 0),
      ]
    );

    res.redirect(`/admin/estoque/produto/${productId}`);
  } catch (err) {
    console.error(err);
    res.status(500).send("Erro ao criar variação (talvez SKU duplicado ou cor+tamanho repetido).");
  }
});

// =========================
// ESTOQUE (ADMIN) - MOVIMENTAR (IN / OUT)
// =========================
app.post("/admin/estoque/variacao/:id/movimentar", requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    if (req.session.user.role !== "admin") return res.status(403).send("Acesso negado.");

    const variantId = req.params.id;
    const { type, quantity, reason, return_to } = req.body;

    const qty = Number(quantity);
    if (!["IN", "OUT"].includes(type)) return res.status(400).send("Tipo inválido.");
    if (!Number.isInteger(qty) || qty <= 0) return res.status(400).send("Quantidade inválida.");

    await client.query("BEGIN");

    // trava a linha para evitar duas pessoas mexendo ao mesmo tempo
    const vRes = await client.query(
      "SELECT id, stock FROM product_variants WHERE id = $1 FOR UPDATE",
      [variantId]
    );
    if (vRes.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(404).send("Variação não encontrada.");
    }

    const currentStock = vRes.rows[0].stock;
    let newStock = currentStock;

    if (type === "IN") newStock = currentStock + qty;
    if (type === "OUT") {
      newStock = currentStock - qty;
      if (newStock < 0) {
        await client.query("ROLLBACK");
        return res.status(400).send("Saída maior que o estoque atual.");
      }
    }

    // registra histórico
    await client.query(
      `INSERT INTO stock_movements (variant_id, type, quantity, reason, created_by)
       VALUES ($1, $2, $3, $4, $5)`,
      [variantId, type, qty, reason?.trim() || null, req.session.user.id]
    );

    // atualiza estoque
    await client.query(
      "UPDATE product_variants SET stock = $1, updated_at = NOW() WHERE id = $2",
      [newStock, variantId]
    );

    await client.query("COMMIT");

    // volta para a página que chamou
    return res.redirect(return_to || "/admin/estoque");
  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    return res.status(500).send("Erro ao movimentar estoque.");
  } finally {
    client.release();
  }
});
// =========================
// ESTOQUE (ADMIN) - HISTÓRICO
// =========================
app.get("/admin/estoque/historico", requireAuth, async (req, res) => {
  try {
    if (req.session.user.role !== "admin") return res.status(403).send("Acesso negado.");

    const result = await pool.query(
      `SELECT m.id, m.type, m.quantity, m.reason, m.created_at,
              v.sku, v.color, v.size,
              p.name AS product_name,
              u.name AS created_by_name
       FROM stock_movements m
       JOIN product_variants v ON v.id = m.variant_id
       JOIN products p ON p.id = v.product_id
       LEFT JOIN users u ON u.id = m.created_by
       ORDER BY m.created_at DESC
       LIMIT 200`
    );

    res.render("admin_estoque_historico", {
      user: req.session.user,
      movements: result.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Erro ao carregar histórico.");
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Servidor rodando na porta", PORT);
});
