require("dotenv").config();

const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const multer = require("multer");
const nodemailer = require("nodemailer");
const path = require("path");
const fs = require("fs");

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || "CHANGE_THIS_SECRET_BEFORE_DEPLOYING";

const ADMIN_EMAIL =
  (process.env.ADMIN_EMAIL || "markobinna120@gmail.com").toLowerCase();

const BANK_DETAILS = {
  accountNumber: "5895097608",
  bank: "Moniepoint",
  accountName: "Ugochi Patricia Etumugo"
};

// ----------------------------------------------------
// APP CONFIG
// ----------------------------------------------------

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const publicDir = path.join(__dirname, "public");
const uploadDir = path.join(__dirname, "uploads");

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

app.use(express.static(publicDir));
app.use("/uploads", express.static(uploadDir));

// ----------------------------------------------------
// DATABASE
// ----------------------------------------------------

const db = new Database(path.join(__dirname, "social_task.db"));

db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  username TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('advertiser','earner')),
  available_balance INTEGER DEFAULT 0,
  pending_balance INTEGER DEFAULT 0,
  status TEXT DEFAULT 'active',
  disabled_until TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS banned_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT,
  username TEXT,
  banned_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS otps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  code TEXT NOT NULL,
  purpose TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS deposits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  account_name TEXT NOT NULL,
  status TEXT DEFAULT 'pending',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  reviewed_at TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  advertiser_id INTEGER NOT NULL,
  platform TEXT NOT NULL,
  platform_icon TEXT,
  task_type TEXT NOT NULL,
  title TEXT NOT NULL,
  link TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  remaining_quantity INTEGER NOT NULL,
  advertiser_price INTEGER NOT NULL,
  earner_reward INTEGER NOT NULL,
  custom_comment TEXT,
  instruction TEXT,
  status TEXT DEFAULT 'available',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(advertiser_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  earner_id INTEGER NOT NULL,
  proof_file TEXT NOT NULL,
  proof_mime TEXT,
  social_username TEXT NOT NULL,
  reward INTEGER NOT NULL,
  status TEXT DEFAULT 'pending',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  reviewed_at TEXT,
  FOREIGN KEY(task_id) REFERENCES tasks(id),
  FOREIGN KEY(earner_id) REFERENCES users(id)
);
`);

// ----------------------------------------------------
// PRICES
// ----------------------------------------------------

const PRICES = {
  like: {
    advertiser: 11,
    earner: 4
  },

  follow: {
    advertiser: 11,
    earner: 5
  },

  comment: {
    advertiser: 11,
    earner: 5
  },

  custom_comment: {
    advertiser: 50,
    earner: 10
  },

  share: {
    advertiser: 11,
    earner: 4
  },

  group_join: {
    advertiser: 17,
    earner: 7
  },

  channel_follow: {
    advertiser: 17,
    earner: 7
  },

  start_bot: {
    advertiser: 20,
    earner: 10
  },

  video_view: {
    advertiser: 12,
    earner: 3
  },

  website_signup: {
    advertiser: 30,
    earner: 10
  },

  vote: {
    advertiser: 30,
    earner: 7
  },

  visit: {
    advertiser: 30,
    earner: 3
  }
};

// ----------------------------------------------------
// PLATFORMS
// ----------------------------------------------------

const PLATFORMS = {
  Facebook: "https://cdn.simpleicons.org/facebook",
  Instagram: "https://cdn.simpleicons.org/instagram",
  TikTok: "https://cdn.simpleicons.org/tiktok",
  X: "https://cdn.simpleicons.org/x",
  YouTube: "https://cdn.simpleicons.org/youtube",
  WhatsApp: "https://cdn.simpleicons.org/whatsapp",
  Telegram: "https://cdn.simpleicons.org/telegram",
  Snapchat: "https://cdn.simpleicons.org/snapchat",
  LinkedIn: "https://cdn.simpleicons.org/linkedin",
  Threads: "https://cdn.simpleicons.org/threads",
  Pinterest: "https://cdn.simpleicons.org/pinterest",
  Reddit: "https://cdn.simpleicons.org/reddit",
  Website: "https://cdn.simpleicons.org/googlechrome"
};

// ----------------------------------------------------
// EMAIL
// ----------------------------------------------------

let transporter = null;

if (
  process.env.SMTP_HOST &&
  process.env.SMTP_USER &&
  process.env.SMTP_PASS
) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 465),
    secure: String(process.env.SMTP_SECURE) !== "false",
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

async function sendOTP(email, code) {
  if (!transporter) {
    console.log(`\n[DEV OTP] ${email}: ${code}\n`);
    return;
  }

  await transporter.sendMail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to: email,
    subject: "Social Task Verification Code",
    text: `Your Social Task verification code is ${code}. This code expires in 10 minutes.`
  });
}

// ----------------------------------------------------
// HELPERS
// ----------------------------------------------------

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function cleanUsername(username) {
  return String(username || "").trim();
}

function nowISO() {
  return new Date().toISOString();
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function setAuthCookie(res, user) {
  const token = createToken(user);

  res.cookie("social_task_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

function getUserFromRequest(req) {
  try {
    const token = req.cookies.social_task_token;

    if (!token) return null;

    const decoded = jwt.verify(token, JWT_SECRET);

    const user = db
      .prepare(
        `
        SELECT id,email,username,role,available_balance,
               pending_balance,status,disabled_until,created_at
        FROM users
        WHERE id = ?
        `
      )
      .get(decoded.id);

    return user || null;
  } catch {
    return null;
  }
}

function isAdmin(user) {
  return !!user && normalizeEmail(user.email) === ADMIN_EMAIL;
}

function requireAuth(req, res, next) {
  const user = getUserFromRequest(req);

  if (!user) {
    return res.status(401).json({
      error: "Please sign in first."
    });
  }

  // Automatically restore temporary disabled account
  if (
    user.status === "disabled" &&
    user.disabled_until &&
    new Date(user.disabled_until) <= new Date()
  ) {
    db.prepare(
      `
      UPDATE users
      SET status='active', disabled_until=NULL
      WHERE id=?
      `
    ).run(user.id);

    user.status = "active";
    user.disabled_until = null;
  }

  if (user.status === "banned") {
    return res.status(403).json({
      error: "Your account has been banned."
    });
  }

  if (user.status === "disabled") {
    return res.status(403).json({
      error:
        "Your account has been disabled and will be enabled in the next 7 days."
    });
  }

  req.user = user;

  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({
        error: "You do not have permission to perform this action."
      });
    }

    next();
  };
}

function requireAdmin(req, res, next) {
  if (!isAdmin(req.user)) {
    return res.status(403).json({
      error: "Admin access only."
    });
  }

  next();
}

function generateOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function getTaskPrice(type) {
  return PRICES[type] || null;
}

function getTaskInstruction(type, customInstruction) {
  if (type === "video_view") {
    return "You must watch at least 30 seconds.";
  }

  return custom
