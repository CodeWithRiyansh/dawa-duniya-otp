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
// ENV VARIABLES
// ======================================================
const PORT = process.env.PORT || 3000;
const { JWT_SECRET, EMAIL_USER, EMAIL_PASS } = process.env;

if (!JWT_SECRET || !EMAIL_USER || !EMAIL_PASS) {
  console.error("❌ Missing ENV variables");
  process.exit(1);
}

// ======================================================
// SECURITY & CSP FIX (The Mac/Mobile Fix)
// ======================================================
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        // ✅ Isse aapke HTML ke andar likha code aur Lottie animations chalne lagenge
        scriptSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com", "https://cdnjs.cloudflare.com"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
        imgSrc: ["'self'", "data:", "https://*"],
        connectSrc: ["'self'", "https://dawa-duniya-otp.vercel.app", "https://open.kickbox.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
  })
);

app.use(
  cors({
    origin: ["http://localhost:3000", "https://dawa-duniya-otp.vercel.app"],
    methods: ["GET", "POST"],
    credentials: true
  })
);

app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());
app.use(morgan("dev"));
app.use(express.static(path.join(__dirname, "public")));

// ======================================================
// RATE LIMITER
// ======================================================
const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 20, // Real world ke liye 20 kaafi hai
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "Too many OTP requests. 5 min baad try karein." }
});

app.use("/send-otp", otpLimiter);

// ======================================================
// NODEMAILER & VALIDATION
// ======================================================
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const allowedDomains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com", "rediffmail.com", "protonmail.com"];
const otpAttempts = {};

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: EMAIL_USER, pass: EMAIL_PASS }
});

// ======================================================
// ROUTES
// ======================================================

app.get("/health", (req, res) => res.status(200).json({ success: true, message: "🚀 Dawa Duniya Backend Running" }));

app.post("/send-otp", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: "Sahi email daalo bhai!" });
    }

    const domain = email.split("@")[1].toLowerCase();
    if (!allowedDomains.includes(domain)) {
      return res.status(400).json({ success: false, message: "Sirf trusted email (Gmail/Yahoo etc.) chalenge." });
    }

    // Disposable Check
    try {
      const response = await axios.get(`https://open.kickbox.com/v1/disposable/${domain}`);
      if (response.data.disposable) {
        return res.status(400).json({ success: false, message: "Temp email allowed nahi hai!" });
      }
    } catch (e) { console.log("Kickbox API down, skipping check."); }

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const hashedOtp = await bcrypt.hash(otp, 10);
    const vToken = jwt.sign({ email, otp: hashedOtp }, JWT_SECRET, { expiresIn: "5m" });

    await transporter.sendMail({
      from: `"Dawa Duniya" <${EMAIL_USER}>`,
      to: email,
      subject: "Dawa Duniya Login OTP",
      html: `<div style="font-family:Arial;padding:20px"><h2>OTP Verification</h2><p>Your OTP is:</p><h1 style="color:#00a884">${otp}</h1><p>Valid for 5 mins.</p></div>`
    });

    return res.status(200).json({ success: true, vToken });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Server error!" });
  }
});

app.post("/verify-otp", async (req, res) => {
  try {
    const { userOtp, vToken } = req.body;
    if (!userOtp || !vToken) return res.status(400).json({ success: false, message: "OTP required!" });

    const decoded = jwt.verify(vToken, JWT_SECRET);
    const isMatch = await bcrypt.compare(String(userOtp), decoded.otp);

    if (!isMatch) return res.status(400).json({ success: false, message: "Galat OTP!" });

    const loginToken = jwt.sign({ email: decoded.email }, JWT_SECRET, { expiresIn: "1h" });

    res.cookie("dawaToken", loginToken, {
      httpOnly: true,
      secure: true, // Vercel par HTTPS hota hai toh true rakhein
      sameSite: "none", // Cross-domain ke liye "none" zaroori hai
      maxAge: 3600000
    });

    return res.status(200).json({ success: true, token: loginToken });
  } catch (err) {
    return res.status(400).json({ success: false, message: "OTP expire ho gaya!" });
  }
});

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// Fallback for SPA
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

const server = app.listen(PORT, () => console.log(`🚀 SERVER RUNNING ON ${PORT}`));

module.exports = app;