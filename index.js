const express = require("express");
const nodemailer = require("nodemailer");
const path = require("path");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");

require("dotenv").config();

const app = express();

// ======================================================
// ENV CHECK
// ======================================================
const { JWT_SECRET, EMAIL_USER, EMAIL_PASS } = process.env;

if (!JWT_SECRET || !EMAIL_USER || !EMAIL_PASS) {
  console.error("❌ Missing ENV variables");
  process.exit(1);
}

// ======================================================
// SECURITY
// ======================================================
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        objectSrc: ["'none'"],
      },
    },
  })
);

// ======================================================
// CORS
// ======================================================
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "https://dawa-duniya-otp.vercel.app",
    ],
    methods: ["GET", "POST"],
    credentials: true,
  })
);

// ======================================================
// MIDDLEWARE
// ======================================================
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());
app.use(morgan("dev"));
app.use(express.static(path.join(__dirname, "public")));

// ======================================================
// RATE LIMIT
// ======================================================
const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  message: {
    success: false,
    message: "Too many OTP requests. Try after 5 minutes.",
  },
});

app.use("/send-otp", otpLimiter);
app.use("/send-link", otpLimiter);

// ======================================================
// VALIDATION
// ======================================================
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ======================================================
// TRUST SYSTEM
// ======================================================
const otpAttemptsByEmail = new Map();
const otpAttemptsByIP = new Map();
const trustScore = new Map();

// ======================================================
// EMAIL TRANSPORT
// ======================================================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS,
  },
});

// ======================================================
// HELPERS
// ======================================================
function getClientIP(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.socket.remoteAddress
  );
}

async function isDisposableEmail(email) {
  try {
    const res = await axios.get(
      `https://open.kickbox.com/v1/disposable/${email}`
    );
    return res.data.disposable;
  } catch {
    return false;
  }
}

function updateTrust(email, domain, disposable) {
  let score = trustScore.get(email) || 0;

  const trusted = [
    "gmail.com",
    "outlook.com",
    "yahoo.com",
    "icloud.com",
    "hotmail.com",
  ];

  if (trusted.includes(domain)) score += 2;
  if (disposable) score -= 3;

  trustScore.set(email, score);
  return score;
}

// ======================================================
// ROUTES
// ======================================================

// HEALTH
app.get("/health", (req, res) => {
  res.json({ success: true, message: "API running 🚀" });
});

// HOME
app.get("/", (req, res) => {
  res.json({ success: true, message: "Dawa Duniya Auth API" });
});

// ======================================================
// OTP FLOW
// ======================================================
app.post("/send-otp", async (req, res) => {
  try {
    const { email } = req.body;
    const ip = getClientIP(req);

    if (!email || !emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: "Invalid email format",
      });
    }

    const domain = email.split("@")[1].toLowerCase();

    // RATE LIMIT LOGIC
    const emailCount = otpAttemptsByEmail.get(email) || 0;
    const ipCount = otpAttemptsByIP.get(ip) || 0;

    if (emailCount >= 3) {
      return res.status(429).json({
        success: false,
        message: "Too many OTP requests for this email",
      });
    }

    if (ipCount >= 10) {
      return res.status(429).json({
        success: false,
        message: "Too many requests from IP",
      });
    }

    otpAttemptsByEmail.set(email, emailCount + 1);
    otpAttemptsByIP.set(ip, ipCount + 1);

    // DISPOSABLE CHECK
    const disposable = await isDisposableEmail(email);

    // TRUST SCORE
    const score = updateTrust(email, domain, disposable);

    if (disposable && score < 0) {
      return res.status(400).json({
        success: false,
        message: "Temporary email not allowed",
      });
    }

    let requireCaptcha = score <= 0 || disposable;

    // OTP
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const hashedOtp = await bcrypt.hash(otp, 10);

    const vToken = jwt.sign(
      { email, otp: hashedOtp },
      JWT_SECRET,
      { expiresIn: "5m" }
    );

    await transporter.sendMail({
      from: `"Dawa Duniya" <${EMAIL_USER}>`,
      to: email,
      subject: "OTP Verification",
      html: `
        <h2>Your OTP</h2>
        <h1>${otp}</h1>
        <p>Valid for 5 minutes</p>
      `,
    });

    return res.json({
      success: true,
      vToken,
      requireCaptcha,
      trustScore: score,
      availableMethods: {
        otp: true,
        emailLink: true,
      },
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

// ======================================================
// VERIFY OTP
// ======================================================
app.post("/verify-otp", async (req, res) => {
  try {
    const { userOtp, vToken } = req.body;

    const decoded = jwt.verify(vToken, JWT_SECRET);

    const match = await bcrypt.compare(
      String(userOtp),
      decoded.otp
    );

    if (!match) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    const token = jwt.sign(
      { email: decoded.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

   res.cookie("dawaToken", login, {
  httpOnly: true,
  secure: true,
  sameSite: "none",
});

    trustScore.set(decoded.email, (trustScore.get(decoded.email) || 0) + 1);

    return res.json({ success: true, token });
  } catch {
    return res.status(400).json({
      success: false,
      message: "OTP expired or invalid",
    });
  }
});

// ======================================================
// LINK FLOW
// ======================================================
app.post("/send-link", async (req, res) => {
  try {
    const { email } = req.body;

    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false });
    }

    const token = jwt.sign({ email }, JWT_SECRET, {
      expiresIn: "10m",
    });

    const BASE_URL =
  process.env.BASE_URL ||
  "https://dawa-duniya-otp.vercel.app";

const link = `${BASE_URL}/verify-email?token=${token}`;

    await transporter.sendMail({
      from: `"Dawa Duniya" <${EMAIL_USER}>`,
      to: email,
      subject: "Verify Email",
      html: `<a href="${link}">Click to verify</a>`,
    });

    return res.json({ success: true });
  } catch {
    return res.status(500).json({ success: false });
  }
});

// ======================================================
// VERIFY LINK
// ======================================================
app.get("/verify-email", (req, res) => {
  try {
    const { token } = req.query;

    const decoded = jwt.verify(token, JWT_SECRET);

    const login = jwt.sign(
      { email: decoded.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.cookie("dawaToken", login, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 3600000,
    });

    return res.redirect("https://dawa-duniya-otp.vercel.app/dashboard.html");
  } catch {
    return res.status(400).send("Invalid link");
  }
});

// ======================================================
// EXPORT
// ======================================================
module.exports = app;