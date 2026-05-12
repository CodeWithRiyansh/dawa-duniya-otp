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

// ==============================
// ENV CHECK
// ==============================
if (
  !process.env.JWT_SECRET ||
  !process.env.EMAIL_USER ||
  !process.env.EMAIL_PASS
) {
  console.error("❌ Missing ENV variables");
}

const JWT_SECRET = process.env.JWT_SECRET;

// ==============================
// SECURITY MIDDLEWARE
// ==============================
app.use(helmet());

app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "https://dawa-duniya-otp.vercel.app"
    ],
    methods: ["GET", "POST"],
    credentials: true
  })
);

app.use(express.json({ limit: "10kb" }));

app.use(cookieParser());

app.use(morgan("dev"));

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

// ==============================
// RATE LIMIT
// ==============================
const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,

  max: 3,

  message: {
    success: false,
    message:
      "Too many OTP requests 😅 Try again after 5 minutes."
  },

  standardHeaders: true,
  legacyHeaders: false
});

app.use("/send-otp", otpLimiter);

// ==============================
// EMAIL VALIDATION
// ==============================
const emailRegex =
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const allowedDomains = [
  "gmail.com",
  "yahoo.com",
  "outlook.com",
  "hotmail.com",
  "icloud.com",
  "rediffmail.com",
  "protonmail.com"
];

// ==============================
// OTP ATTEMPTS
// ==============================
const otpAttempts = {};

// ==============================
// NODEMAILER
// ==============================
const transporter =
  nodemailer.createTransport({
    host: "smtp.gmail.com",

    port: 465,

    secure: true,

    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

// ==============================
// HEALTH ROUTE
// ==============================
app.get("/health", (req, res) => {
  return res.status(200).json({
    success: true,
    message:
      "🚀 Dawa Duniya Secure Backend Running"
  });
});

// ==============================
// SEND OTP
// ==============================
app.post(
  "/send-otp",
  async (req, res) => {
    try {
      const { email } = req.body;

      // ==========================
      // EMAIL REQUIRED
      // ==========================
      if (!email) {
        return res.status(400).json({
          success: false,
          message:
            "Email required hai!"
        });
      }

      // ==========================
      // EMAIL FORMAT
      // ==========================
      if (!emailRegex.test(email)) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid email format!"
        });
      }

      const domain =
        email
          .split("@")[1]
          .toLowerCase();

      // ==========================
      // DOMAIN CHECK
      // ==========================
      if (
        !allowedDomains.includes(domain)
      ) {
        console.log(
          `❌ Blocked Domain: ${domain}`
        );

        return res.status(400).json({
          success: false,
          message:
            "Nice try bro 😏 Trusted email use karo."
        });
      }

      // ==========================
      // DISPOSABLE EMAIL CHECK
      // ==========================
      try {
        const response =
          await axios.get(
            `https://open.kickbox.com/v1/disposable/${domain}`
          );

        if (
          response.data.disposable ===
          true
        ) {
          return res.status(400).json({
            success: false,
            message:
              "Temporary email allowed nahi hai!"
          });
        }
      } catch (err) {
        console.log(
          "⚠ Disposable API failed"
        );
      }

      // ==========================
      // OTP GENERATE
      // ==========================
      const otp = String(
        Math.floor(
          100000 +
            Math.random() * 900000
        )
      );

      // ==========================
      // HASH OTP
      // ==========================
      const hashedOtp =
        await bcrypt.hash(otp, 10);

      // ==========================
      // VERIFY TOKEN
      // ==========================
      const vToken = jwt.sign(
        {
          email,
          otp: hashedOtp
        },

        JWT_SECRET,

        {
          expiresIn: "5m"
        }
      );

      // ==========================
      // SEND EMAIL
      // ==========================
      await transporter.sendMail({
        from: `"Dawa Duniya" <${process.env.EMAIL_USER}>`,

        to: email,

        subject:
          "Dawa Duniya Login OTP",

        html: `
        <div style="font-family:Arial;padding:20px">
          
          <h2>
            Dawa Duniya OTP Verification
          </h2>

          <p>Your OTP is:</p>

          <h1 style="letter-spacing:5px;color:#00a884">
            ${otp}
          </h1>

          <p>
            Ye OTP sirf 5 minute tak valid hai.
          </p>

        </div>
        `
      });

      console.log(
        `✅ OTP Sent to ${email}`
      );

      return res.status(200).json({
        success: true,
        message:
          "OTP sent successfully!",

        vToken
      });

    } catch (err) {
      console.error(
        "❌ Send OTP Error:",
        err
      );

      return res.status(500).json({
        success: false,
        message:
          "OTP bhejne mein error aaya!"
      });
    }
  }
);

// ==============================
// VERIFY OTP
// ==============================
app.post(
  "/verify-otp",
  async (req, res) => {
    try {
      const { userOtp, vToken } =
        req.body;

      if (!userOtp || !vToken) {
        return res.status(400).json({
          success: false,
          message:
            "OTP aur token required hai!"
        });
      }

      // ==========================
      // VERIFY TOKEN
      // ==========================
      const decoded = jwt.verify(
        vToken,
        JWT_SECRET
      );

      // ==========================
      // OTP ATTEMPTS
      // ==========================
      if (
        !otpAttempts[decoded.email]
      ) {
        otpAttempts[
          decoded.email
        ] = 0;
      }

      if (
        otpAttempts[
          decoded.email
        ] >= 5
      ) {
        return res.status(429).json({
          success: false,
          message:
            "Too many wrong OTP attempts 😅"
        });
      }

      // ==========================
      // COMPARE OTP
      // ==========================
      const isMatch =
        await bcrypt.compare(
          String(userOtp),
          decoded.otp
        );

      if (!isMatch) {
        otpAttempts[
          decoded.email
        ]++;

        return res.status(400).json({
          success: false,
          message:
            "Galat OTP hai!"
        });
      }

      // RESET ATTEMPTS
      otpAttempts[
        decoded.email
      ] = 0;

      // ==========================
      // LOGIN TOKEN
      // ==========================
      const loginToken = jwt.sign(
        {
          email: decoded.email
        },

        JWT_SECRET,

        {
          expiresIn: "1h"
        }
      );

      // ==========================
      // SECURE COOKIE
      // ==========================
      res.cookie(
        "dawaToken",
        loginToken,
        {
          httpOnly: true,

          secure: true,

          sameSite: "strict",

          maxAge:
            60 * 60 * 1000
        }
      );

      console.log(
        `✅ Login Success: ${decoded.email}`
      );

      return res.status(200).json({
        success: true,
        token: loginToken
      });

    } catch (err) {
      console.error(
        "❌ Verify OTP Error:",
        err.message
      );

      return res.status(400).json({
        success: false,
        message:
          "OTP expire ya invalid hai!"
      });
    }
  }
);

// ==============================
// LOGOUT
// ==============================
app.post("/logout", (req, res) => {
  res.clearCookie("dawaToken");

  return res.status(200).json({
    success: true,
    message: "Logout successful"
  });
});

// ==============================
// 404 ROUTE
// ==============================
app.use((req, res) => {
  res.status(404).sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

// ==============================
// GLOBAL ERROR HANDLER
// ==============================
app.use(
  (err, req, res, next) => {
    console.error(
      "❌ Global Error:",
      err
    );

    return res.status(500).json({
      success: false,
      message:
        "Internal Server Error"
    });
  }
);

module.exports = app;