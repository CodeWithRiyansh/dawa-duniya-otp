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

const {
  JWT_SECRET,
  EMAIL_USER,
  EMAIL_PASS
} = process.env;

// ======================================================
// ENV CHECK
// ======================================================
if (!JWT_SECRET || !EMAIL_USER || !EMAIL_PASS) {
  console.error("❌ Missing ENV variables");
  process.exit(1);
}

// ======================================================
// SECURITY
// ======================================================
app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "https://dawa-duniya-otp.vercel.app"
    ],
    credentials: true,
    methods: ["GET", "POST"]
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

// ======================================================
// RATE LIMITER
// ======================================================
const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,

  max: 100,

  standardHeaders: true,

  legacyHeaders: false,

  message: {
    success: false,
    message:
      "Too many OTP requests 😅 Try again later."
  }
});

app.use("/send-otp", otpLimiter);

// ======================================================
// EMAIL VALIDATION
// ======================================================
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

// ======================================================
// OTP ATTEMPTS
// ======================================================
const otpAttempts = {};

// ======================================================
// NODEMAILER
// ======================================================
const transporter =
  nodemailer.createTransport({
    service: "gmail",

    auth: {
      user: EMAIL_USER,
      pass: EMAIL_PASS
    }
  });

// ======================================================
// VERIFY SMTP
// ======================================================
transporter.verify((error) => {
  if (error) {
    console.log("❌ SMTP ERROR");
    console.log(error);
  } else {
    console.log("✅ SMTP SERVER READY");
  }
});

// ======================================================
// HEALTH ROUTE
// ==================
// ====================================

app.get("/test-mail", async (req, res) => {

  try {

    await transporter.sendMail({
      from: EMAIL_USER,
      to: EMAIL_USER,
      subject: "SMTP TEST",
      text: "Dawa Duniya SMTP Working"
    });

    console.log("✅ TEST MAIL SENT");

    res.send("MAIL SENT");

  } catch (err) {

    console.log("❌ TEST MAIL ERROR");

    console.log(err);

    res.send("MAIL FAILED");
  }
});
app.get("/health", (req, res) => {
  return res.status(200).json({
    success: true,
    message:
      "🚀 Dawa Duniya Backend Running"
  });
});

// ======================================================
// SEND OTP
// ======================================================
app.post(
  "/send-otp",
  async (req, res) => {
    try {
      const { email } = req.body;

      // ==========================================
      // EMAIL REQUIRED
      // ==========================================
      if (!email) {
        return res.status(400).json({
          success: false,
          message:
            "Email required hai!"
        });
      }

      // ==========================================
      // EMAIL FORMAT
      // ==========================================
      if (!emailRegex.test(email)) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid email format!"
        });
      }

      // ==========================================
      // DOMAIN CHECK
      // ==========================================
      const domain =
        email
          .split("@")[1]
          .toLowerCase();

      if (
        !allowedDomains.includes(domain)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Nice try bro 😏 Trusted email use karo."
        });
      }

      // ==========================================
      // DISPOSABLE EMAIL CHECK
      // ==========================================
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
      } catch (apiError) {
        console.log(
          "⚠ Disposable email API failed"
        );
      }

      // ==========================================
      // OTP GENERATE
      // ==========================================
      const otp = String(
        Math.floor(
          100000 +
            Math.random() * 900000
        )
      );

      // ==========================================
      // HASH OTP
      // ==========================================
      const hashedOtp =
        await bcrypt.hash(otp, 10);

      // ==========================================
      // VERIFY TOKEN
      // ==========================================
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

      // ==========================================
      // SEND MAIL
      // ==========================================
      await transporter.sendMail({
        from: `"Dawa Duniya" <${EMAIL_USER}>`,

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
        `✅ OTP SENT TO ${email}`
      );

      return res.status(200).json({
        success: true,
        message:
          "OTP sent successfully!",

        vToken
      });

    } catch (err) {

      console.log("❌ SEND OTP ERROR");

      console.log(err);

      return res.status(500).json({
        success: false,
        message:
          "OTP bhejne mein error aaya!"
      });
    }
  }
);

// ======================================================
// VERIFY OTP
// ======================================================
app.post(
  "/verify-otp",
  async (req, res) => {
    try {

      const {
        userOtp,
        vToken
      } = req.body;

      // ==========================================
      // REQUIRED CHECK
      // ==========================================
      if (!userOtp || !vToken) {
        return res.status(400).json({
          success: false,
          message:
            "OTP aur token required hai!"
        });
      }

      // ==========================================
      // VERIFY TOKEN
      // ==========================================
      const decoded = jwt.verify(
        vToken,
        JWT_SECRET
      );

      // ==========================================
      // ATTEMPTS
      // ==========================================
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

      // ==========================================
      // OTP COMPARE
      // ==========================================
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

      // ==========================================
      // RESET ATTEMPTS
      // ==========================================
      otpAttempts[
        decoded.email
      ] = 0;

      // ==========================================
      // LOGIN TOKEN
      // ==========================================
      const loginToken = jwt.sign(
        {
          email: decoded.email
        },

        JWT_SECRET,

        {
          expiresIn: "1h"
        }
      );

      // ==========================================
      // COOKIE
      // ==========================================
      res.cookie(
        "dawaToken",
        loginToken,
        {
          httpOnly: true,

          secure: false,

          sameSite: "strict",

          maxAge:
            60 * 60 * 1000
        }
      );

      console.log(
        `✅ LOGIN SUCCESS ${decoded.email}`
      );

      return res.status(200).json({
        success: true,
        token: loginToken
      });

    } catch (err) {

      console.log(
        "❌ VERIFY OTP ERROR"
      );

      console.log(err);

      return res.status(400).json({
        success: false,
        message:
          "OTP expire ya invalid hai!"
      });
    }
  }
);

// ======================================================
// LOGOUT
// ======================================================
app.post("/logout", (req, res) => {

  res.clearCookie("dawaToken");

  return res.status(200).json({
    success: true,
    message:
      "Logout successful"
  });
});

// ======================================================
// HOME ROUTE
// ======================================================
app.get("/", (req, res) => {

  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

// ======================================================
// 404 ROUTE
// ======================================================
app.use((req, res) => {

  return res.status(404).json({
    success: false,
    message:
      "Route not found"
  });
});

// ======================================================
// GLOBAL ERROR
// ======================================================
app.use(
  (err, req, res, next) => {

    console.log(
      "❌ GLOBAL ERROR"
    );

    console.log(err);

    return res.status(500).json({
      success: false,
      message:
        "Internal Server Error"
    });
  }
);

// ======================================================
// EXPORT
// ======================================================
module.exports = app;

// ======================================================
// LOCAL SERVER
// ======================================================
if (process.env.NODE_ENV !== "production") {

  app.listen(PORT, () => {

    console.log(
      `🚀 SERVER RUNNING ON ${PORT}`
    );
  });
}