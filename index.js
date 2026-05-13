const express = require("express");
const nodemailer = require("nodemailer");
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

// ================= ENV =================
const { JWT_SECRET, EMAIL_USER, EMAIL_PASS } = process.env;

if (!JWT_SECRET || !EMAIL_USER || !EMAIL_PASS) {
  console.error("❌ Missing ENV variables");
  process.exit(1);
}

// ================= MIDDLEWARE =================
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());
app.use(morgan("dev"));

// ================= FIXED CSP (IMPORTANT FOR GOOGLE FONTS) =================
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com"
        ],
        styleSrcElem: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com"
        ],
        fontSrc: [
          "'self'",
          "https://fonts.gstatic.com"
        ],
        imgSrc: ["'self'", "data:", "https://*"],
        connectSrc: [
          "'self'",
          "https://open.kickbox.com"
        ],
        objectSrc: ["'none'"]
      }
    }
  })
);

// ================= CORS =================
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "http://127.0.0.1:5500",
      "https://dawa-duniya-otp.vercel.app"
    ],
    methods: ["GET", "POST"],
    credentials: true,
  })
);

// ================= RATE LIMIT =================
app.use(
  "/send-otp",
  rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
  })
);

// ================= EMAIL =================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS,
  },
});

// ================= VALIDATION =================
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const allowedDomains = [
  "gmail.com",
  "yahoo.com",
  "outlook.com",
  "hotmail.com",
  "icloud.com",
  "protonmail.com",
];

// ================= HEALTH =================
app.get("/health", (req, res) => {
  res.json({
    success: true,
    message: "OTP API Running 🚀",
  });
});

// ================= SEND OTP =================
app.post("/send-otp", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: "Invalid email",
      });
    }

    const domain = email.split("@")[1].toLowerCase();

    if (!allowedDomains.includes(domain)) {
      return res.status(400).json({
        success: false,
        message: "Email provider not allowed",
      });
    }

    // Kickbox check
    try {
      const r = await axios.get(
        `https://open.kickbox.com/v1/disposable/${email}`
      );

      if (r.data.disposable) {
        return res.status(400).json({
          success: false,
          message: "Temporary email not allowed",
        });
      }
    } catch {}

    // OTP
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const hashedOtp = await bcrypt.hash(otp, 10);

    const vToken = jwt.sign(
      { email: email.toLowerCase(), otp: hashedOtp },
      JWT_SECRET,
      { expiresIn: "5m" }
    );

    await transporter.sendMail({
      from: EMAIL_USER,
      to: email,
      subject: "OTP Verification",
      html: `
        <div style="font-family:Arial;padding:20px">
          <h2>OTP Verification</h2>
          <h1 style="color:#00a884">${otp}</h1>
          <p>Valid for 5 minutes</p>
        </div>
      `,
    });

    res.json({ success: true, vToken });

  } catch (err) {
    console.log(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ================= VERIFY OTP =================
app.post("/verify-otp", async (req, res) => {
  try {
    const { userOtp, vToken } = req.body;

    if (!userOtp || !vToken) {
      return res.status(400).json({
        success: false,
        message: "OTP required",
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(vToken, JWT_SECRET);
    } catch {
      return res.status(400).json({
        success: false,
        message: "OTP expired",
      });
    }

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

    return res.json({ success: true, token });

  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

module.exports = app;