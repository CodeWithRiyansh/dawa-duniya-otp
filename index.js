const express = require("express");
const nodemailer = require("nodemailer");
const path = require("path");
const jwt = require("jsonwebtoken");
const axios = require("axios");
require("dotenv").config();

const app = express();

// ==============================
// CONFIG
// ==============================
const PORT = process.env.PORT || 3000;

const JWT_SECRET =
  process.env.JWT_SECRET || "DawaDuniya_Noida_Secret_99";

// ==============================
// MIDDLEWARE
// ==============================
app.use(express.json());

app.use(
  express.static(path.join(__dirname, "public"))
);

// ==============================
// EMAIL VALIDATION
// ==============================
const emailRegex =
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Allowed trusted domains only
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
// NODEMAILER
// ==============================
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,

  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Verify SMTP connection
transporter.verify((error) => {
  if (error) {
    console.log("❌ SMTP Error:", error);
  } else {
    console.log("✅ SMTP Server Ready");
  }
});

// ==============================
// HEALTH CHECK
// ==============================
app.get("/health", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Server Running Fine 🚀"
  });
});

// ==============================
// SEND OTP ROUTE
// ==============================
app.post("/send-otp", async (req, res) => {
  try {
    const { email } = req.body;

    // ==========================
    // EMAIL REQUIRED
    // ==========================
    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email required hai!"
      });
    }

    // ==========================
    // EMAIL FORMAT CHECK
    // ==========================
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: "Invalid email format!"
      });
    }

    // ==========================
    // DOMAIN CHECK
    // ==========================
    const domain =
      email.split("@")[1].toLowerCase();

    if (!allowedDomains.includes(domain)) {
      console.log(
        `❌ Blocked Domain: ${domain}`
      );

      return res.status(400).json({
        success: false,
        message:
          "Sirf trusted email providers allowed hain!"
      });
    }

    // ==========================
    // TEMP EMAIL CHECK
    // ==========================
    try {
      const response = await axios.get(
        `https://open.kickbox.com/v1/disposable/${domain}`
      );

      if (response.data.disposable === true) {
        return res.status(400).json({
          success: false,
          message:
            "Temporary email allowed nahi hai!"
        });
      }
    } catch (apiErr) {
      console.log(
        "⚠ Disposable API failed, using whitelist only"
      );
    }

    // ==========================
    // OTP GENERATE
    // ==========================
    const otp = Math.floor(
      100000 + Math.random() * 900000
    );

    // ==========================
    // VERIFY TOKEN
    // ==========================
    const vToken = jwt.sign(
      {
        email,
        otp
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

      subject: "Dawa Duniya Login OTP",

      html: `
        <div style="font-family:Arial;padding:20px">
          <h2>Dawa Duniya OTP Verification</h2>

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

    console.log(`✅ OTP Sent to ${email}`);

    return res.status(200).json({
      success: true,
      message: "OTP sent successfully!",
      vToken
    });

  } catch (err) {
    console.error("❌ Send OTP Error:", err);

    return res.status(500).json({
      success: false,
      message: "OTP bhejne mein error aaya!"
    });
  }
});

// ==============================
// VERIFY OTP ROUTE
// ==============================
app.post("/verify-otp", (req, res) => {
  try {
    const { userOtp, vToken } = req.body;

    // ==========================
    // CHECK INPUTS
    // ==========================
    if (!userOtp || !vToken) {
      return res.status(400).json({
        success: false,
        message: "OTP aur token required hai!"
      });
    }

    // ==========================
    // VERIFY JWT
    // ==========================
    const decoded = jwt.verify(
      vToken,
      JWT_SECRET
    );

    // ==========================
    // OTP MATCH
    // ==========================
    if (
      String(decoded.otp) ===
      String(userOtp)
    ) {
      // Login token
      const loginToken = jwt.sign(
        {
          email: decoded.email
        },
        JWT_SECRET,
        {
          expiresIn: "1h"
        }
      );

      console.log(
        `✅ Login Success: ${decoded.email}`
      );

      return res.status(200).json({
        success: true,
        token: loginToken
      });
    }

    return res.status(400).json({
      success: false,
      message: "Galat OTP hai!"
    });

  } catch (err) {
    console.error(
      "❌ Verify OTP Error:",
      err.message
    );

    return res.status(400).json({
      success: false,
      message: "OTP expire ya invalid hai!"
    });
  }
});

// ==============================
// 404 ROUTE FIX
// EXPRESS 5 SAFE VERSION
// ==============================
app.use((req, res) => {
  res.status(404).sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

// ==============================
// SERVER START
// ==============================
app.listen(PORT, () => {
  console.log(
    `🚀 Dawa Duniya Secure Server Running On Port ${PORT}`
  );
});