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
const PORT = process.env.PORT || 3000;
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
// RATE LIMIT (GLOBAL OTP PROTECTION)
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

// ======================================================
// VALIDATION
// ======================================================
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ======================================================
// TRUST + TRACKING SYSTEM
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
  } catch (err) {
    return false; // fail-safe allow
  }
}

function updateTrust(email, domain, disposable) {
  let score = trustScore.get(email) || 0;

  const trustedDomains = [
    "gmail.com",
    "outlook.com",
    "yahoo.com",
    "icloud.com",
    "hotmail.com",
  ];

  if (trustedDomains.includes(domain)) score += 2;
  if (disposable) score -= 3;

  trustScore.set(email, score);
  return score;
}

// ======================================================
// ROUTES
// ======================================================

// HEALTH
app.get("/health", (req, res) => {
  res.json({
    success: true,
    message: "OTP API Running 🚀",
  });
});

// HOME
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Dawa Duniya OTP API is running",
  });
});

// ======================================================
// SEND OTP (UPGRADED ENGINE)
// ======================================================
app.post("/send-otp", async (req, res) => {
  try {
    const { email } = req.body;
    const ip = getClientIP(req);

    // STEP 1: format check
    if (!email || !emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: "Invalid email format",
      });
    }

    const domain = email.split("@")[1].toLowerCase();

    // ======================================================
    // STEP 2: RATE LIMITING (EMAIL + IP)
    // ======================================================
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
        message: "Too many requests from this IP",
      });
    }

    otpAttemptsByEmail.set(email, emailCount + 1);
    otpAttemptsByIP.set(ip, ipCount + 1);

    // ======================================================
    // STEP 3: DISPOSABLE CHECK
    // ======================================================
    const disposable = await isDisposableEmail(email);

    // ======================================================
    // STEP 4: TRUST SCORE
    // ======================================================
    const score = updateTrust(email, domain, disposable);

    // ======================================================
    // STEP 5: DECISION ENGINE
    // ======================================================
    if (disposable && score < 0) {
      return res.status(400).json({
        success: false,
        message: "Temporary email addresses are not allowed",
      });
    }

    // CAPTCHA TRIGGER FLAG (frontend use)
    let requireCaptcha = false;
    if (score <= 0 || disposable) {
      requireCaptcha = true;
    }

    // ======================================================
    // OTP GENERATION
    // ======================================================
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const hashedOtp = await bcrypt.hash(otp, 10);

    const vToken = jwt.sign(
      { email, otp: hashedOtp },
      JWT_SECRET,
      { expiresIn: "5m" }
    );

    // ======================================================
    // SEND EMAIL
    // ======================================================
    await transporter.sendMail({
      from: `"Dawa Duniya" <${EMAIL_USER}>`,
      to: email,
      subject: "OTP Verification",
      html: `
        <div style="font-family:Arial;padding:20px">
          <h2>OTP Verification</h2>
          <p>Your OTP is:</p>
          <h1 style="color:#00a884">${otp}</h1>
          <p>Valid for 5 minutes</p>
        </div>
      `,
    });

    return res.json({
      success: true,
      vToken,
      requireCaptcha,
      trustScore: score,
    });
  } catch (err) {
    console.log(err);
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

    if (!userOtp || !vToken) {
      return res.status(400).json({
        success: false,
        message: "OTP required",
      });
    }

    const decoded = jwt.verify(vToken, JWT_SECRET);

    const isMatch = await bcrypt.compare(
      String(userOtp),
      decoded.otp
    );

    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    // update trust after success
    const current = trustScore.get(decoded.email) || 0;
    trustScore.set(decoded.email, current + 1);

    const loginToken = jwt.sign(
      { email: decoded.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.cookie("dawaToken", loginToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 3600000,
    });

    return res.json({
      success: true,
      token: loginToken,
    });
  } catch (err) {
    return res.status(400).json({
      success: false,
      message: "OTP expired or invalid",
    });
  }
});

// ======================================================
// EXPORT (VERCEL)
// ======================================================
module.exports = app;