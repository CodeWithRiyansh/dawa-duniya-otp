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
// ENV
// ======================================================

const { JWT_SECRET, EMAIL_USER, EMAIL_PASS } = process.env;

if (!JWT_SECRET || !EMAIL_USER || !EMAIL_PASS) {
  console.log("❌ Missing ENV variables");
  process.exit(1);
}

// ======================================================
// SECURITY
// ======================================================

app.use(
  helmet({
    contentSecurityPolicy: false,
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
    message: "Too many requests. Try again later.",
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
    "icloud.com",
    "hotmail.com",
    "yahoo.com",
  ];

  if (trusted.includes(domain)) score += 2;

  if (disposable) score -= 3;

  trustScore.set(email, score);

  return score;
}

// ======================================================
// HEALTH
// ======================================================

app.get("/health", (req, res) => {
  res.json({
    success: true,
    message: "API running 🚀",
  });
});

// ======================================================
// HOME
// ======================================================

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ======================================================
// SEND OTP
// ======================================================

app.post("/send-otp", async (req, res) => {
  try {
    const { email } = req.body;

    const ip = getClientIP(req);

    if (!email || !emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: "Invalid email",
      });
    }

    const domain = email.split("@")[1].toLowerCase();

    // RATE LIMIT LOGIC

    const emailCount = otpAttemptsByEmail.get(email) || 0;
    const ipCount = otpAttemptsByIP.get(ip) || 0;

    if (emailCount >= 3) {
      return res.status(429).json({
        success: false,
        message: "Too many OTP requests",
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

    const score = updateTrust(email, domain, disposable);

    if (disposable && score < 0) {
      return res.status(400).json({
        success: false,
        message: "Temporary email not allowed",
      });
    }

    // OTP

    const otp = String(
      Math.floor(100000 + Math.random() * 900000)
    );

    console.log("OTP:", otp);

    const hashedOtp = await bcrypt.hash(otp, 10);

    const vToken = jwt.sign(
      {
        email,
        otp: hashedOtp,
      },
      JWT_SECRET,
      {
        expiresIn: "5m",
      }
    );

    await transporter.sendMail({
      from: `"Dawa Duniya" <${EMAIL_USER}>`,
      to: email,
      subject: "OTP Verification",
      html: `
        <div style="font-family:sans-serif;padding:20px;">
          <h2>Dawa Duniya OTP</h2>
          <h1>${otp}</h1>
          <p>Valid for 5 minutes.</p>
        </div>
      `,
    });

    return res.json({
      success: true,
      vToken,
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
        message: "OTP or token missing",
      });
    }

    let decoded;

    try {
      decoded = jwt.verify(vToken, JWT_SECRET);
    } catch (err) {
      return res.status(400).json({
        success: false,
        message: "OTP expired or invalid",
      });
    }

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

    const token = jwt.sign(
      {
        email: decoded.email,
      },
      JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    return res.json({
      success: true,
      token,
    });
  } catch (err) {
    console.log(err);

    return res.status(500).json({
      success: false,
      message: "Verification failed",
    });
  }
});

// ======================================================
// SEND EMAIL LINK
// ======================================================

app.post("/send-link", async (req, res) => {
  try {
    const { email } = req.body;

    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: "Invalid email",
      });
    }

    const token = jwt.sign(
      { email },
      JWT_SECRET,
      {
        expiresIn: "10m",
      }
    );

    const BASE_URL =
      process.env.BASE_URL ||
      "https://dawa-duniya-otp.vercel.app";

    const link = `${BASE_URL}/verify-email?token=${token}`;

    await transporter.sendMail({
      from: `"Dawa Duniya" <${EMAIL_USER}>`,
      to: email,
      subject: "Verify Email",
      html: `
        <div style="font-family:sans-serif;padding:20px;">
          <h2>Email Verification</h2>
          <a href="${link}">
            Verify Email
          </a>
        </div>
      `,
    });

    return res.json({
      success: true,
    });
  } catch (err) {
    console.log(err);

    return res.status(500).json({
      success: false,
      message: "Failed to send link",
    });
  }
});

// ======================================================
// VERIFY EMAIL
// ======================================================

app.get("/verify-email", (req, res) => {
  try {
    const { token } = req.query;

    if (!token) {
      return res.status(400).send("Invalid link");
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    const loginToken = jwt.sign(
      {
        email: decoded.email,
      },
      JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Verifying...</title>
      </head>

      <body style="background:#0f172a;color:white;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;">
      
        <h2>Email Verified 🚀</h2>

        <script>
          localStorage.setItem("dawaToken","${loginToken}");
          window.location.href="/dashboard.html";
        </script>

      </body>
      </html>
    `);
  } catch (err) {
    console.log(err);

    return res.status(400).send(`
      <h2>Invalid or expired link</h2>
    `);
  }
});

// ======================================================
// SERVER
// ======================================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});

module.exports = app;