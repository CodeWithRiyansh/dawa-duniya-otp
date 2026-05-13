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
const { JWT_SECRET, EMAIL_USER, EMAIL_PASS, ABSTRACT_API_KEY, BASE_URL } = process.env;

if (!JWT_SECRET || !EMAIL_USER || !EMAIL_PASS || !BASE_URL) {
  console.log("❌ Missing ENV variables");
  process.exit(1);
}

// ======================================================
// MIDDLEWARE & SECURITY
// ======================================================
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());
app.use(morgan("dev"));
app.use(express.static(path.join(__dirname, "public")));

// ======================================================
// RATE LIMITING (Double Click & Spam Protection)
// ======================================================
const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 Minutes
  max: 10,
  message: { success: false, message: "Too many requests. Please try after 5 minutes." }
});

// ======================================================
// GLOBAL HELPERS
// ======================================================
const otpCooldown = new Map();
const verifyAttempts = new Map();
const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/;

// ======================================================
// ADVANCED EMAIL VALIDATOR (The Tester Logic ✅)
// ======================================================
async function validateRealEmail(email) {
  try {
    const domain = email.split("@")[1]?.toLowerCase();

    // 1. ✅ ALLOW: Specific Domains (Whitelisting)
    const allowedDomains = ["healthians.com", "teleperformance.com", "gmail.com", "outlook.com", "yahoo.com", "icloud.com"];
    if (allowedDomains.includes(domain)) return { valid: true };

    // 2. ❌ BLOCK: Known Temp Mail Domains (Hard-coded list)
    const blockedDomains = [
      "tempmail.com", "yopmail.com", "10minutemail.com", "guerrillamail.com", 
      "mailinator.com", "trashmail.com", "fakeinbox.com", "temp-mail.org"
    ];
    if (blockedDomains.includes(domain)) {
      return { valid: false, message: "Temporary/Fake emails are not allowed" };
    }

    // 3. 🔍 DEEP CHECK: Abstract API (Disposable & Deliverability)
    if (ABSTRACT_API_KEY) {
      const response = await axios.get(
        `https://emailvalidation.abstractapi.com/v1/?api_key=${ABSTRACT_API_KEY}&email=${email}`
      );
      const data = response.data;

      if (data.is_disposable_email?.value === true) {
        return { valid: false, message: "Disposable email detected" };
      }
      if (data.deliverability === "UNDELIVERABLE") {
        return { valid: false, message: "This email inbox does not exist" };
      }
    }

    // 4. ✅ FAIL-SAFE: Allow if everything else passes
    return { valid: true };

  } catch (err) {
    console.log("Validation Error (Failing Open):", err.message);
    return { valid: true }; // Real users block na ho agar API down ho
  }
}

// ======================================================
// EMAIL TRANSPORT
// ======================================================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: EMAIL_USER, pass: EMAIL_PASS }
});

// ======================================================
// ROUTES
// ======================================================

app.post("/send-otp", otpLimiter, async (req, res) => {
  try {
    let { email } = req.body;
    if (!email || !emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: "Invalid email format" });
    }

    email = email.toLowerCase().trim();

    // COOLDOWN CHECK (1 minute)
    const lastRequest = otpCooldown.get(email);
    if (lastRequest && Date.now() - lastRequest < 60000) {
      return res.status(429).json({ success: false, message: "Please wait 60 seconds" });
    }

    // VALIDATION
    const validation = await validateRealEmail(email);
    if (!validation.valid) {
      return res.status(400).json({ success: false, message: validation.message });
    }

    // GENERATE OTP
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const hashedOtp = await bcrypt.hash(otp, 10);
    otpCooldown.set(email, Date.now());

    // CREATE JWT (vToken)
    const vToken = jwt.sign({ email, otp: hashedOtp }, JWT_SECRET, { expiresIn: "5m" });

    // SEND MAIL
    await transporter.sendMail({
      from: `"Dawa Duniya" <${EMAIL_USER}>`,
      to: email,
      subject: "Dawa Duniya Login OTP",
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
          <h2 style="color: #00ffcc;">Dawa Duniya</h2>
          <p>Your verification code is:</p>
          <h1 style="letter-spacing: 5px; color: #3b82f6;">${otp}</h1>
          <p>This OTP is valid for 5 minutes. Do not share it with anyone.</p>
        </div>`
    });

    return res.json({ success: true, vToken });

  } catch (err) {
    console.error("SEND OTP ERROR:", err);
    return res.status(500).json({ success: false, message: "Server error. Try again later." });
  }
});

app.post("/verify-otp", async (req, res) => {
  try {
    const { userOtp, vToken } = req.body;
    if (!userOtp || !vToken) return res.status(400).json({ success: false, message: "Missing Data" });

    // ATTEMPTS LIMIT
    const attempts = verifyAttempts.get(vToken) || 0;
    if (attempts >= 5) return res.status(429).json({ success: false, message: "Too many attempts. Send OTP again." });

    // VERIFY TOKEN
    let decoded;
    try {
      decoded = jwt.verify(vToken, JWT_SECRET);
    } catch {
      return res.status(400).json({ success: false, message: "OTP expired or invalid" });
    }

    // MATCH OTP
    const match = await bcrypt.compare(String(userOtp), decoded.otp);
    if (!match) {
      verifyAttempts.set(vToken, attempts + 1);
      return res.status(400).json({ success: false, message: "Incorrect OTP" });
    }

    // CREATE FINAL LOGIN TOKEN
    const token = jwt.sign({ email: decoded.email }, JWT_SECRET, { expiresIn: "1h" });

    res.cookie("dawaToken", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 3600000
    });

    return res.json({ success: true, token });

  } catch (err) {
    return res.status(500).json({ success: false, message: "Verification failed" });
  }
});

// ======================================================
// EXPORT FOR VERCEL / SERVER
// ======================================================
module.exports = app;
const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
}