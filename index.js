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
  console.error("Missing ENV variables");
  process.exit(1);
}

// ================= MIDDLEWARE =================
app.use(express.json());
app.use(cookieParser());
app.use(morgan("dev"));

// ================= SECURITY =================
app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

// ================= CORS FIX =================
app.use(
  cors({
    origin: true,
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

// ================= SEND OTP =================
app.post("/send-otp", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !emailRegex.test(email)) {
      return res.json({ success: false, message: "Invalid email" });
    }

    const domain = email.split("@")[1];

    if (!allowedDomains.includes(domain)) {
      return res.json({ success: false, message: "Domain not allowed" });
    }

    // FIXED KICKBOX
    try {
      const r = await axios.get(
        `https://open.kickbox.com/v1/disposable/${email}`
      );

      if (r.data.disposable) {
        return res.json({
          success: false,
          message: "Temporary email not allowed",
        });
      }
    } catch {}

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const hashed = await bcrypt.hash(otp, 10);

    const vToken = jwt.sign(
      { email, otp: hashed },
      JWT_SECRET,
      { expiresIn: "5m" }
    );

    await transporter.sendMail({
      from: EMAIL_USER,
      to: email,
      subject: "OTP",
      html: `<h2>Your OTP: ${otp}</h2>`,
    });

    res.json({ success: true, vToken });

  } catch (err) {
    res.json({ success: false, message: "Server error" });
  }
});

// ================= VERIFY OTP =================
app.post("/verify-otp", async (req, res) => {
  try {
    const { userOtp, vToken } = req.body;

    const decoded = jwt.verify(vToken, JWT_SECRET);

    const match = await bcrypt.compare(userOtp, decoded.otp);

    if (!match) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    const token = jwt.sign(
      { email: decoded.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    return res.json({ success: true, token });

  } catch {
    return res.json({ success: false, message: "OTP expired" });
  }
});

module.exports = app;