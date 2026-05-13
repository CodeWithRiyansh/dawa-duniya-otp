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
// SECURITY (Helmet FIXED)
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
      "https://dawa-duniya-otp.vercel.app"
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
// RATE LIMIT (OTP SAFE)
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

const allowedDomains = [
  "gmail.com",
  "yahoo.com",
  "outlook.com",
  "hotmail.com",
  "icloud.com",
  "rediffmail.com",
  "protonmail.com",
];

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
// HEALTH CHECK
// ======================================================
app.get("/health", (req, res) => {
  res.json({
    success: true,
    message: "OTP API Running 🚀",
  });
});

// ======================================================
// HOME
// ======================================================
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Dawa Duniya OTP API is running",
  });
});

// ======================================================
// SEND OTP
// ======================================================
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
        message: "Only trusted email providers allowed",
      });
    }

    // Kickbox disposable check (FIXED)
    try {
      const response = await axios.get(
        `https://open.kickbox.com/v1/disposable/${email}`
      );

      if (response.data.disposable) {
        return res.status(400).json({
          success: false,
          message: "Temporary email not allowed",
        });
      }
    } catch (err) {
      console.log("Kickbox skipped");
    }

    // OTP generate
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const hashedOtp = await bcrypt.hash(otp, 10);

    const vToken = jwt.sign(
      { email, otp: hashedOtp },
      JWT_SECRET,
      { expiresIn: "5m" }
    );

    // send email
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