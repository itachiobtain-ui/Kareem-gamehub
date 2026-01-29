/**
 * Kareem GameHub — Single File Full-Stack Demo (Node.js + Express + SQLite)
 * Features:
 * - Register / Login / Logout (sessions)
 * - User profile (bio + favorite genres)
 * - Browse games with search + filters
 * - Game details: favorites + rating + comments
 * - Recommendations based on favorite genres + popularity
 * - Admin dashboard: add games + list users + view logs
 *
 * Run locally:
 *   1) npm install
 *   2) node app.js --seed
 *   3) node app.js
 * Open:
 *   http://localhost:3000
 *
 * Demo Admin (after seed):
 *   username: admin
 *   password: Admin12345!
 */

require("dotenv").config();
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const morgan = require("morgan");
const { nanoid } = require("nanoid");

// ------------------------- Config -------------------------
const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || "./data.sqlite";
const SESSION_SECRET = process.env.SESSION_SECRET || "dev_secret_change_me";
const NODE_ENV = process.env.NODE_ENV || "development";

// ------------------------- App & DB -------------------------
const app = express();
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

// ------------------------- Migrations -------------------------
function migrate() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      bio TEXT DEFAULT '',
      favorite_genres TEXT DEFAULT '[]',
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS games (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      genres TEXT NOT NULL,
      platforms TEXT NOT NULL,
      difficulty TEXT NOT NULL,
      release_year INTEGER NOT NULL,
      rating_avg REAL NOT NULL DEFAULT 0,
      rating_count INTEGER NOT NULL DEFAULT 0,
      cover_url TEXT DEFAULT '',
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS favorites (
      user_id TEXT NOT NULL,
      game_id TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (user_id, game_id)
    );

    CREATE TABLE IF NOT EXISTS ratings (
      user_id TEXT NOT NULL,
      game_id TEXT NOT NULL,
      rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      PRIMARY KEY (user_id, game_id)
    );

    CREATE TABLE IF NOT EXISTS comments (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      game_id TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      actor_user_id TEXT,
      action TEXT NOT NULL,
      meta TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_games_title ON games(title);
    CREATE INDEX IF NOT EXISTS idx_comments_game ON comments(game_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
  `);
}

function seed() {
  const now = Date.now();

  const userCount = db.prepare(`SELECT COUNT(*) as c FROM users`).get().c;
  const gameCount = db.prepare(`SELECT COUNT(*) as c FROM games`).get().c;

  const insertUser = db.prepare(`
    INSERT INTO users (id, username, email, password_hash, role, bio, favorite_genres, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertGame = db.prepare(`
    INSERT INTO games (id, title, description, genres, platforms, difficulty, release_year, cover_url, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  if (userCount === 0) {
    const adminId = nanoid();
    const userId = nanoid();

    insertUser.run(
      adminId,
      "admin",
      "admin@example.com",
      bcrypt.hashSync("Admin12345!", 12),
      "admin",
      "I manage the platform.",
      JSON.stringify(["RPG", "Strategy", "Indie"]),
      now
    );

    insertUser.run(
      userId,
      "player1",
      "player1@example.com",
      bcrypt.hashSync("Player12345!", 12),
      "user",
      "I love discovering hidden gems.",
      JSON.stringify(["Action", "Adventure", "Indie"]),
      now
    );
  }

  if (gameCount === 0) {
    const games = [
      {
        title: "Nebula Raiders",
        description: "Fast-paced space roguelite with build crafting and boss fights.",
        genres: ["Action", "Roguelite", "Indie"],
        platforms: ["PC", "PS", "Xbox"],
        difficulty: "hard",
        release_year: 2023
      },
      {
        title: "Kingdom Tactician",
        description: "Turn-based strategy with deep economy and tactical battles.",
        genres: ["Strategy", "Tactics"],
        platforms: ["PC", "Switch"],
        difficulty: "medium",
        release_year: 2022
      },
      {
        title: "Forest Whisper",
        description: "Chill exploration adventure with puzzles and cozy vibes.",
        genres: ["Adventure", "Puzzle", "Cozy"],
        platforms: ["PC", "PS"],
        difficulty: "easy",
        release_year: 2021
      },
      {
        title: "Dungeon Chronicle",
        description: "Classic RPG with party management and branching quests.",
        genres: ["RPG", "Adventure"],
        platforms: ["PC"],
        difficulty: "medium",
        release_year: 2020
      },
      {
        title: "Circuit Sprint",
        description: "Arcade racing with time trials and online leaderboards (offline demo).",
        genres: ["Racing", "Arcade"],
        platforms: ["PC", "Xbox"],
        difficulty: "easy",
        release_year: 2019
      }
    ];

    for (const g of games) {
      insertGame.run(
        nanoid(),
        g.title,
        g.description,
        JSON.stringify(g.genres),
        JSON.stringify(g.platforms),
        g.difficulty,
        g.release_year,
        "",
        now
      );
    }
  }
}

migrate();

if (process.argv.includes("--seed")) {
  seed();
  console.log("Seed complete.");
  process.exit(0);
}

// ------------------------- Middlewares -------------------------
app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan("dev"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

// simple rate-limit (in-memory)
const rateState = new Map();
app.use((req, res, next) => {
  const windowMs = 60_000;
  const max = 250;
  const key = req.ip || "unknown";
  const now = Date.now();
  const cur = rateState.get(key) || { count: 0, resetAt: now + windowMs };
  if (now > cur.resetAt) {
    cur.count = 0;
    cur.resetAt = now + windowMs;
  }
  cur.count++;
  rateState.set(key, cur);

  res.setHeader("X-RateLimit-Limit", String(max));
  res.setHeader("X-RateLimit-Remaining", String(Math.max(0, max - cur.count)));

  if (cur.count > max) {
    return res
      .status(429)
      .send(renderPage("Too Many Requests", renderError("Rate limit exceeded. Try again."), req));
  }
  next();
});

// attach user to req
app.use((req, res, next) => {
  req.currentUser = req.session.user || null;
  next();
});

// ------------------------- Helpers -------------------------
function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function cleanStr(s, max = 200) {
  if (typeof s !== "string") return "";
  const t = s.trim();
  return t.length > max ? t.slice(0, max) : t;
}

function isEmail(s) {
  return typeof s === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
}

function parseJsonArray(s) {
  try {
    const a = JSON.parse(s);
    return Array.isArray(a) ? a : [];
  } catch {
    return [];
  }
}

function safeInt(v, def = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : def;
}

function requireAuth(req, res, next) {
  if (!req.currentUser) return res.redirect("/login");
  next();
}

function requireAdmin(req, res, next) {
  if (!req.currentUser) return res.redirect("/login");
  if (req.currentUser.role !== "admin") {
    return res.status(403).send(renderPage("Forbidden", renderError("Not allowed."), req));
  }
  next();
}

function audit(actorUserId, action, metaObj) {
  db.prepare(`
    INSERT INTO audit_logs (id, actor_user_id, action, meta, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(nanoid(), actorUserId || null, action, JSON.stringify(metaObj || {}), Date.now());
}

function recomputeGameRating(gameId) {
  const agg = db.prepare(`SELECT AVG(rating) as avg, COUNT(*) as cnt FROM ratings WHERE game_id=?`).get(gameId);
  db.prepare(`UPDATE games SET rating_avg=?, rating_count=? WHERE id=?`).run(
    Number(agg.avg || 0),
    Number(agg.cnt || 0),
    gameId
  );
}

function scoreGameForUser(game, userGenres) {
  const gGenres = parseJsonArray(game.genres);
  let score = 0;
  for (const ug of userGenres) if (gGenres.includes(ug)) score += 5;
  if (userGenres.includes("Cozy") && game.difficulty === "easy") score += 2;
  if (userGenres.includes("Roguelite") && game.difficulty === "hard") score += 2;
  score += (game.rating_avg || 0) * 1.2;
  score += Math.min(2, (game.rating_count || 0) / 10);
  score += Math.max(0, (game.release_year - 2018)) * 0.2;
  return score;
}

// ------------------------- UI (single-file HTML) -------------------------
const STYLE = `
:root{--bg:#0b0f19;--card:#121a2b;--txt:#e6edf7;--muted:#aab4c3;--accent:#6ea8fe;--line:#1b2742}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,Segoe UI,Arial;background:var(--bg);color:var(--txt)}
a{color:inherit;text-decoration:none}
.container{max-width:1100px;margin:0 auto;padding:18px}
.topbar{display:flex;justify-content:space-between;align-items:center;padding:12px 18px;background:#0a1222;border-bottom:1px solid #18223a;position:sticky;top:0}
.brand{font-weight:900;letter-spacing:.5px}
.nav{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.btn{background:var(--accent);border:none;color:#061021;padding:10px 12px;border-radius:10px;font-weight:800;cursor:pointer}
.btn:hover{filter:brightness(1.05)}
.btn.secondary{background:#223356;color:#e6edf7}
.inline{display:inline}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px;margin:14px 0;box-shadow:0 10px 30px rgba(0,0,0,.25)}
.hero{padding:10px 0}
.muted{color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.game{display:block;background:#0d1527;border:1px solid #1b2742;border-radius:14px;padding:14px;min-height:170px}
.game:hover{border-color:#2c3e6d}
.gameTitle{font-weight:900;font-size:18px}
.meta{display:flex;gap:10px;flex-wrap:wrap;color:var(--muted);margin-top:6px}
.tags{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
.tag{background:#0d1b33;border:1px solid #223356;color:#cfe1ff;padding:4px 8px;border-radius:999px;font-size:12px}
.badge{background:#122a1f;border:1px solid #1c4b36;color:#bff2d2;padding:4px 8px;border-radius:999px;font-size:12px}
.desc{color:var(--muted);line-height:1.35;margin:10px 0 0}
.stack{display:grid;gap:10px}
input,textarea,select{width:100%;padding:10px;border-radius:12px;border:1px solid #223356;background:#0b1426;color:var(--txt)}
.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.filters{display:grid;grid-template-columns:2fr 1fr 1fr 1fr auto;gap:10px}
hr{border:none;border-top:1px solid #223356;margin:14px 0}
.comment{padding:12px;border-top:1px solid #223356}
.commentHead{display:flex;justify-content:space-between;gap:10px;margin-bottom:6px}
.table{display:grid;gap:6px}
.tr{display:grid;grid-template-columns:1.2fr 1.6fr .6fr .8fr;gap:10px;padding:10px;border:1px solid #223356;border-radius:12px;background:#0d1527}
.th{font-weight:900;background:#0b1426}
.logs .log{border:1px solid #223356;border-radius:12px;padding:10px;background:#0d1527;margin:10px 0}
pre{white-space:pre-wrap;word-wrap:break-word;color:#d7e6ff;margin:8px 0 0}
.footer{padding:18px;text-align:center;color:var(--muted)}
@media (max-width:900px){.filters{grid-template-columns:1fr;}}
`;

function navHtml(req) {
  const u = req.currentUser;
  const authLinks = u
    ? `
      <a href="/">Home</a>
      <a href="/recommended">Recommended</a>
      <a href="/profile">Profile</a>
      ${u.role === "admin" ? `<a href="/admin">Admin</a>` : ``}
      <form action="/logout" method="POST" class="inline">
        <button class="btn" type="submit">Logout</button>
      </form>
    `
    : `
      <a href="/">Home</a>
      <a href="/login">Login</a>
      <a href="/register">Register</a>
    `;
  return `
    <header class="topbar">
      <a class="brand" href="/">Kareem GameHub</a>
      <nav class="nav">${authLinks}</nav>
    </header>
  `;
}

function renderPage(title, bodyHtml, req) {
  return `
  <!doctype html>
  <html lang="en">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>${escapeHtml(title)} • Kareem GameHub</title>
    <style>${STYLE}</style>
  </head>
  <body>
    ${navHtml(req)}
    <main class="container">${bodyHtml}</main>
    <footer class="footer"><small>Kareem GameHub • single-file demo</small></footer>
  </body>
  </html>
  `;
}

function renderError(message) {
  return `
    <div class="card">
      <h2>Error</h2>
      <p>${escapeHtml(message)}</p>
      <a class="btn" href="/">Go Home</a>
    </div>
  `;
}

function renderHero(title, subtitle) {
  return `
    <section class="hero">
      <h1>${escapeHtml(title)}</h1>
      <p class="muted">${escapeHtml(subtitle)}</p>
    </section>
  `;
}

function gameCard(g) {
  const genres = parseJsonArray(g.genres).slice(0, 4);
  return `
    <a class="game" href="/game/${escapeHtml(g.id)}">
      <div class="gameTitle">${escapeHtml(g.title)}</div>
      <div class="meta">
        <span>⭐ ${(g.rating_avg || 0).toFixed(1)}</span>
        <span>(${g.rating_count || 0})</span>
        <span>${escapeHtml(String(g.release_year))}</span>
      </div>
      <div class="tags">
        ${genres.map(t => `<span class="tag">${escapeHtml(t)}</span>`).join("")}
      </div>
      <p class="desc">${escapeHtml(g.description)}</p>
    </a>
  `;
}

// ------------------------- Routes -------------------------

// Home / browse
app.get("/", (req, res) => {
  const q = cleanStr(req.query.q || "", 60);
  const genre = cleanStr(req.query.genre || "", 30);
  const platform = cleanStr(req.query.platform || "", 30);
  const difficulty = cleanStr(req.query.difficulty || "", 10);

  let where = [];
  let params = [];

  if (q) {
    where.push(`(title LIKE ? OR description LIKE ?)`);
    params.push(`%${q}%`, `%${q}%`);
  }
  if (difficulty) {
    where.push(`difficulty = ?`);
    params.push(difficulty);
  }
  if (genre) {
    where.push(`genres LIKE ?`);
    params.push(`%${genre}%`);
  }
  if (platform) {
    where.push(`platforms LIKE ?`);
    params.push(`%${platform}%`);
  }

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const games = db
    .prepare(
      `
      SELECT * FROM games
      ${whereSql}
      ORDER BY rating_avg DESC, rating_count DESC, release_year DESC
      LIMIT 60
    `
    )
    .all(...params);

  const body = `
    ${renderHero("Kareem GameHub", "Search, filter, rate, favorite, and get recommendations.")}
    <section class="card">
      <form class="filters" method="GET" action="/">
        <input name="q" placeholder="Search games..." value="${escapeHtml(q)}"/>
        <input name="genre" placeholder="Genre (e.g. RPG)" value="${escapeHtml(genre)}"/>
        <input name="platform" placeholder="Platform (e.g. PC)" value="${escapeHtml(platform)}"/>
        <select name="difficulty">
          <option value="">Difficulty</option>
          <option value="easy" ${difficulty === "easy" ? "selected" : ""}>easy</option>
          <option value="medium" ${difficulty === "medium" ? "selected" : ""}>medium</option>
          <option value="hard" ${difficulty === "hard" ? "selected" : ""}>hard</option>
        </select>
        <button class="btn" type="submit">Apply</button>
      </form>
    </section>
    <section class="grid">
      ${games.map(gameCard).join("") || `<div class="card">No games found.</div>`}
    </section>
  `;

  res.send(renderPage("Home", body, req));
});

// Auth: Register
app.get("/register", (req, res) => {
  const body = `
    <div class="card">
      <h2>Create account</h2>
      <form method="POST" action="/register" class="stack">
        <label>Username</label>
        <input name="username" required maxlength="30"/>
        <label>Email</label>
        <input name="email" required/>
        <label>Password</label>
        <input name="password" type="password" required minlength="8"/>
        <button class="btn" type="submit">Register</button>
      </form>
      <p class="muted">Already have an account? <a href="/login"><b>Login</b></a></p>
    </div>
  `;
  res.send(renderPage("Register", body, req));
});

app.post("/register", (req, res) => {
  const username = cleanStr(req.body.username, 30);
  const email = cleanStr(req.body.email, 80).toLowerCase();
  const password = String(req.body.password || "");

  if (!username || !email || !password) {
    return res.status(400).send(renderPage("Register", renderError("Missing fields."), req));
  }
  if (!isEmail(email)) {
    return res.status(400).send(renderPage("Register", renderError("Invalid email."), req));
  }
  if (password.length < 8) {
    return res.status(400).send(renderPage("Register", renderError("Password must be at least 8 characters."), req));
  }

  const exists = db.prepare(`SELECT 1 FROM users WHERE username=? OR email=?`).get(username, email);
  if (exists) {
    return res.status(400).send(renderPage("Register", renderError("Username or email already used."), req));
  }

  const id = nanoid();
  db.prepare(
    `INSERT INTO users (id, username, email, password_hash, role, bio, favorite_genres, created_at)
     VALUES (?, ?, ?, ?, 'user', '', '[]', ?)`
  ).run(id, username, email, bcrypt.hashSync(password, 12), Date.now());

  audit(id, "register", { username, email });
  req.session.user = { id, username, role: "user" };
  res.redirect("/profile");
});

// Auth: Login
app.get("/login", (req, res) => {
  const body = `
    <div class="card">
      <h2>Login</h2>
      <form method="POST" action="/login" class="stack">
        <label>Username or Email</label>
        <input name="identity" required/>
        <label>Password</label>
        <input name="password" type="password" required/>
        <button class="btn" type="submit">Login</button>
      </form>
      <p class="muted">No account? <a href="/register"><b>Register</b></a></p>
    </div>
  `;
  res.send(renderPage("Login", body, req));
});

app.post("/login", (req, res) => {
  const identity = cleanStr(req.body.identity, 120);
  const password = String(req.body.password || "");

  const user =
    db.prepare(`SELECT * FROM users WHERE username=?`).get(identity) ||
    db.prepare(`SELECT * FROM users WHERE email=?`).get(identity.toLowerCase());

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    audit(null, "login_failed", { identity });
    return res.status(401).send(renderPage("Login", renderError("Invalid credentials."), req));
  }

  req.session.user = { id: user.id, username: user.username, role: user.role };
  audit(user.id, "login_success", { username: user.username });
  res.redirect("/");
});

// Auth: Logout
app.post("/logout", (req, res) => {
  const uid = req.currentUser?.id || null;
  req.session.destroy(() => {
    if (uid) audit(uid, "logout", {});
    res.redirect("/");
  });
});

// Profile
app.get("/profile", requireAuth, (req, res) => {
  const u = db.prepare(`SELECT * FROM users WHERE id=?`).get(req.currentUser.id);
  const genres = parseJsonArray(u.favorite_genres);

  const body = `
    <div class="card">
      <h2>Profile</h2>
      <p class="muted">Signed in as <b>${escapeHtml(u.username)}</b> (${escapeHtml(u.role)})</p>
      <form method="POST" action="/profile" class="stack">
        <label>Bio</label>
        <textarea name="bio" rows="3" maxlength="300">${escapeHtml(u.bio || "")}</textarea>

        <label>Favorite genres (comma separated)</label>
        <input name="favorite_genres" value="${escapeHtml(genres.join(", "))}" placeholder="Action, RPG, Indie"/>

        <button class="btn" type="submit">Save</button>
      </form>
    </div>
  `;
  res.send(renderPage("Profile", body, req));
});

app.post("/profile", requireAuth, (req, res) => {
  const bio = cleanStr(req.body.bio || "", 300);
  const fav = cleanStr(req.body.favorite_genres || "", 200);

  const genres = fav
    .split(",")
    .map(s => s.trim())
    .filter(Boolean)
    .slice(0, 12);

  db.prepare(`UPDATE users SET bio=?, favorite_genres=? WHERE id=?`).run(
    bio,
    JSON.stringify(genres),
    req.currentUser.id
  );

  audit(req.currentUser.id, "profile_update", { genresCount: genres.length });
  res.redirect("/profile");
});

// Game details
app.get("/game/:id", (req, res) => {
  const id = cleanStr(req.params.id, 60);
  const game = db.prepare(`SELECT * FROM games WHERE id=?`).get(id);
  if (!game) return res.status(404).send(renderPage("Not found", renderError("Game not found."), req));

  const comments = db
    .prepare(
      `
      SELECT c.*, u.username
      FROM comments c JOIN users u ON u.id=c.user_id
      WHERE c.game_id=?
      ORDER BY c.created_at DESC
      LIMIT 50
    `
    )
    .all(id);

  let myRating = null;
  let isFav = false;

  if (req.currentUser) {
    myRating = db.prepare(`SELECT rating FROM ratings WHERE user_id=? AND game_id=?`).get(req.currentUser.id, id) || null;
    isFav = !!db.prepare(`SELECT 1 FROM favorites WHERE user_id=? AND game_id=?`).get(req.currentUser.id, id);
  }

  const genres = parseJsonArray(game.genres);
  const platforms = parseJsonArray(game.platforms);

  const actionsHtml = req.currentUser
    ? `
      <div class="row">
        <form method="POST" action="/game/${escapeHtml(game.id)}/favorite">
          <button class="btn ${isFav ? "secondary" : ""}" type="submit">${isFav ? "Unfavorite" : "Favorite"}</button>
        </form>

        <form method="POST" action="/game/${escapeHtml(game.id)}/rate" class="inline">
          <select name="rating">
            ${[1,2,3,4,5].map(i => `<option value="${i}" ${(myRating && myRating.rating === i) ? "selected" : ""}>${i}</option>`).join("")}
          </select>
          <button class="btn" type="submit">Rate</button>
        </form>
      </div>
      <hr/>
      <form method="POST" action="/game/${escapeHtml(game.id)}/comment" class="stack">
        <label>Add comment</label>
        <textarea name="content" rows="3" required maxlength="300"></textarea>
        <button class="btn" type="submit">Post</button>
      </form>
    `
    : `<p class="muted">Login to rate, favorite, and comment.</p>`;

  const body = `
    <div class="card">
      <h2>${escapeHtml(game.title)}</h2>
      <div class="meta">
        <span>⭐ ${(game.rating_avg || 0).toFixed(1)}</span>
        <span>(${game.rating_count || 0})</span>
        <span>${escapeHtml(String(game.release_year))}</span>
        <span class="badge">${escapeHtml(game.difficulty)}</span>
        <span class="muted">Platforms: ${platforms.map(escapeHtml).join(", ") || "-"}</span>
      </div>

      <div class="tags">${genres.map(t => `<span class="tag">${escapeHtml(t)}</span>`).join("")}</div>

      <p>${escapeHtml(game.description)}</p>
      ${actionsHtml}
    </div>

    <div class="card">
      <h3>Comments</h3>
      ${
        comments.length
          ? comments
              .map(
                c => `
        <div class="comment">
          <div class="commentHead">
            <b>${escapeHtml(c.username)}</b>
            <span class="muted">${escapeHtml(new Date(c.created_at).toLocaleString())}</span>
          </div>
          <div>${escapeHtml(c.content)}</div>
        </div>
      `
              )
              .join("")
          : `<p class="muted">No comments yet.</p>`
      }
    </div>
  `;

  res.send(renderPage(game.title, body, req));
});

// Favorite toggle
app.post("/game/:id/favorite", requireAuth, (req, res) => {
  const gameId = cleanStr(req.params.id, 60);
  const userId = req.currentUser.id;

  const game = db.prepare(`SELECT id FROM games WHERE id=?`).get(gameId);
  if (!game) return res.status(404).send(renderPage("Not found", renderError("Game not found."), req));

  const exists = db.prepare(`SELECT 1 FROM favorites WHERE user_id=? AND game_id=?`).get(userId, gameId);

  if (exists) {
    db.prepare(`DELETE FROM favorites WHERE user_id=? AND game_id=?`).run(userId, gameId);
    audit(userId, "unfavorite", { gameId });
  } else {
    db.prepare(`INSERT INTO favorites (user_id, game_id, created_at) VALUES (?, ?, ?)`).run(userId, gameId, Date.now());
    audit(userId, "favorite", { gameId });
  }

  res.redirect(`/game/${gameId}`);
});

// Rate a game
app.post("/game/:id/rate", requireAuth, (req, res) => {
  const gameId = cleanStr(req.params.id, 60);
  const userId = req.currentUser.id;
  const rating = safeInt(req.body.rating, 0);

  if (rating < 1 || rating > 5) {
    return res.status(400).send(renderPage("Bad request", renderError("Rating must be 1..5"), req));
  }

  const now = Date.now();
  const existing = db.prepare(`SELECT 1 FROM ratings WHERE user_id=? AND game_id=?`).get(userId, gameId);

  if (existing) {
    db.prepare(`UPDATE ratings SET rating=?, updated_at=? WHERE user_id=? AND game_id=?`).run(rating, now, userId, gameId);
  } else {
    db.prepare(`INSERT INTO ratings (user_id, game_id, rating, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`).run(
      userId,
      gameId,
      rating,
      now,
      now
    );
  }

  recomputeGameRating(gameId);
  audit(userId, "rate", { gameId, rating });
  res.redirect(`/game/${gameId}`);
});

// Comment
app.post("/game/:id/comment", requireAuth, (req, res) => {
  const gameId = cleanStr(req.params.id, 60);
  const userId = req.currentUser.id;
  const content = cleanStr(req.body.content || "", 300);

  if (!content) {
    return res.status(400).send(renderPage("Bad request", renderError("Comment is empty."), req));
  }

  db.prepare(`INSERT INTO comments (id, user_id, game_id, content, created_at) VALUES (?, ?, ?, ?, ?)`).run(
    nanoid(),
    userId,
    gameId,
    content,
    Date.now()
  );

  audit(userId, "comment", { gameId, len: content.length });
  res.redirect(`/game/${gameId}`);
});

// Recommended
app.get("/recommended", requireAuth, (req, res) => {
  const u = db.prepare(`SELECT * FROM users WHERE id=?`).get(req.currentUser.id);
  const userGenres = parseJsonArray(u.favorite_genres);

  const games = db.prepare(`SELECT * FROM games ORDER BY rating_avg DESC, rating_count DESC, release_year DESC LIMIT 200`).all();
  const ranked = games
    .map(g => ({ g, score: scoreGameForUser(g, userGenres) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 30);

  const body = `
    ${renderHero("Recommended", "Based on your favorite genres + ratings + recency.")}
    <div class="card">
      <p class="muted">Your genres: <b>${escapeHtml(userGenres.join(", ") || "None")}</b></p>
      <p class="muted">Tip: update your genres in <a href="/profile"><b>Profile</b></a></p>
    </div>
    <section class="grid">
      ${ranked.map(x => gameCard(x.g)).join("") || `<div class="card">No recommendations.</div>`}
    </section>
  `;
  res.send(renderPage("Recommended", body, req));
});

// Admin
app.get("/admin", requireAdmin, (req, res) => {
  const users = db.prepare(`SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC LIMIT 50`).all();
  const games = db.prepare(`SELECT id, title, release_year, rating_avg, rating_count FROM games ORDER BY created_at DESC LIMIT 50`).all();
  const logs = db.prepare(`SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 30`).all();

  const body = `
    ${renderHero("Admin Dashboard", "Manage games, inspect users, and view audit logs.")}
    <div class="card">
      <h3>Add game</h3>
      <form method="POST" action="/admin/games" class="stack">
        <label>Title</label>
        <input name="title" required maxlength="80"/>
        <label>Description</label>
        <textarea name="description" rows="3" required maxlength="400"></textarea>
        <div class="row">
          <div style="flex:1">
            <label>Genres (comma separated)</label>
            <input name="genres" placeholder="Action, RPG, Indie" required maxlength="120"/>
          </div>
          <div style="flex:1">
            <label>Platforms (comma separated)</label>
            <input name="platforms" placeholder="PC, PS, Xbox" required maxlength="120"/>
          </div>
        </div>
        <div class="row">
          <div style="flex:1">
            <label>Difficulty</label>
            <select name="difficulty">
              <option value="easy">easy</option>
              <option value="medium" selected>medium</option>
              <option value="hard">hard</option>
            </select>
          </div>
          <div style="flex:1">
            <label>Release year</label>
            <input name="release_year" value="2024" />
          </div>
        </div>
        <label>Cover URL (optional)</label>
        <input name="cover_url" placeholder="https://..." maxlength="200"/>
        <button class="btn" type="submit">Create</button>
      </form>
    </div>

    <div class="card">
      <h3>Users</h3>
      <div class="table">
        <div class="tr th"><div>ID</div><div>User</div><div>Role</div><div>Created</div></div>
        ${
          users
            .map(
              u => `<div class="tr">
                <div class="muted">${escapeHtml(u.id.slice(0, 8))}…</div>
                <div>
                  <b>${escapeHtml(u.username)}</b><div class="muted">${escapeHtml(u.email)}</div>
                </div>
                <div>${escapeHtml(u.role)}</div>
                <div class="muted">${escapeHtml(new Date(u.created_at).toLocaleDateString())}</div>
              </div>`
            )
            .join("") || `<p class="muted">No users.</p>`
        }
      </div>
    </div>

    <div class="card">
      <h3>Recent games</h3>
      <div class="table">
        <div class="tr th"><div>ID</div><div>Title</div><div>Stars</div><div>Year</div></div>
        ${
          games
            .map(
              g => `<div class="tr">
                <div class="muted">${escapeHtml(g.id.slice(0, 8))}…</div>
                <div><b>${escapeHtml(g.title)}</b></div>
                <div class="muted">⭐ ${(g.rating_avg || 0).toFixed(1)} (${g.rating_count || 0})</div>
                <div>${escapeHtml(String(g.release_year))}</div>
              </div>`
            )
            .join("") || `<p class="muted">No games.</p>`
        }
      </div>
    </div>

    <div class="card logs">
      <h3>Audit logs</h3>
      ${
        logs
          .map(
            l => `<div class="log">
              <b>${escapeHtml(l.action)}</b>
              <div class="muted">${escapeHtml(new Date(l.created_at).toLocaleString())}</div>
              <pre>${escapeHtml(l.meta)}</pre>
            </div>`
          )
          .join("") || `<p class="muted">No logs.</p>`
      }
    </div>
  `;

  res.send(renderPage("Admin", body, req));
});

app.post("/admin/games", requireAdmin, (req, res) => {
  const title = cleanStr(req.body.title || "", 80);
  const description = cleanStr(req.body.description || "", 400);
  const genres = cleanStr(req.body.genres || "", 120);
  const platforms = cleanStr(req.body.platforms || "", 120);
  const difficulty = cleanStr(req.body.difficulty || "medium", 10);
  const release_year = safeInt(req.body.release_year, 2024);
  const cover_url = cleanStr(req.body.cover_url || "", 200);

  if (!title || !description || !genres || !platforms) {
    return res.status(400).send(renderPage("Admin", renderError("Missing fields."), req));
  }

  const gArr = genres.split(",").map(s => s.trim()).filter(Boolean).slice(0, 12);
  const pArr = platforms.split(",").map(s => s.trim()).filter(Boolean).slice(0, 12);

  db.prepare(
    `INSERT INTO games (id, title, description, genres, platforms, difficulty, release_year, cover_url, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    nanoid(),
    title,
    description,
    JSON.stringify(gArr),
    JSON.stringify(pArr),
    ["easy", "medium", "hard"].includes(difficulty) ? difficulty : "medium",
    release_year,
    cover_url,
    Date.now()
  );

  audit(req.currentUser.id, "admin_add_game", { title });
  res.redirect("/admin");
});

// 404
app.use((req, res) => {
  res.status(404).send(renderPage("Not found", renderError("Page not found."), req));
});

// Start
app.listen(PORT, () => {
  console.log(`Kareem GameHub running on http://localhost:${PORT} (env=${NODE_ENV})`);
});
