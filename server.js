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
app.use(express.static("public"));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Servidor rodando na porta", PORT);
});
