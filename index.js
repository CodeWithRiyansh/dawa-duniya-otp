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

const {
  JWT_SECRET,
  EMAIL_USER,
  EMAIL_PASS,
  ABSTRACT_API_KEY,
  BASE_URL
} = process.env;

// ======================================================
// ENV CHECK
// ======================================================

if (
  !JWT_SECRET ||
  !EMAIL_USER ||
  !EMAIL_PASS ||
  !BASE_URL
) {

  console.log("❌ Missing ENV variables");

  process.exit(1);
}

// ======================================================
// SECURITY
// ======================================================

app.use(
  helmet({
    contentSecurityPolicy:false
  })
);

// ======================================================
// CORS
// ======================================================

app.use(
  cors({
    origin:true,
    credentials:true
  })
);

// ======================================================
// MIDDLEWARE
// ======================================================

app.use(express.json({ limit:"10kb" }));

app.use(cookieParser());

app.use(morgan("dev"));

app.use(
  express.static(
    path.join(__dirname,"public")
  )
);

// ======================================================
// RATE LIMIT
// ======================================================

const otpLimiter = rateLimit({

  windowMs:5 * 60 * 1000,

  max:10,

  message:{
    success:false,
    message:"Too many requests"
  }
});

app.use("/send-otp", otpLimiter);

app.use("/send-link", otpLimiter);

// ======================================================
// HELPERS
// ======================================================

const otpCooldown = new Map();

const verifyAttempts = new Map();

const emailRegex =
/^[a-zA-Z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/;

// ======================================================
// BLOCKED TEMP EMAIL DOMAINS
// ======================================================

const blockedDomains = [

  "tempmail.com",
  "10minutemail.com",
  "guerrillamail.com",
  "mailinator.com",
  "yopmail.com",
  "trashmail.com",
  "fakeinbox.com",
  "temp-mail.org",
  "sharklasers.com",
  "dispostable.com",
  "maildrop.cc",
  "tempmailo.com",
  "moakt.com",
  "getnada.com",
  "emailondeck.com",
  "throwawaymail.com",
  "mailnesia.com",
  "mintemail.com",
  "spamgourmet.com",
  "tempail.com",
  "fake-mail.net"

];

// ======================================================
// EMAIL VALIDATION
// ======================================================

async function validateRealEmail(email) {

  try {

    const domain =
      email.split("@")[1]?.toLowerCase();

    // =========================================
    // TEMP DOMAIN BLOCK
    // =========================================

    if (blockedDomains.includes(domain)) {

      return {
        valid:false,
        message:"Temporary email not allowed"
      };
    }

    // =========================================
    // ABSTRACT API VALIDATION
    // =========================================

    const response = await axios.get(
      `https://emailvalidation.abstractapi.com/v1/?api_key=${ABSTRACT_API_KEY}&email=${email}`
    );

    const data = response.data;

    console.log("EMAIL VALIDATION:", data);

    // =========================================
    // DISPOSABLE EMAIL
    // =========================================

    if (
      data.is_disposable_email?.value === true
    ) {

      return {
        valid:false,
        message:"Temporary email not allowed"
      };
    }

    // =========================================
    // INVALID FORMAT
    // =========================================

    if (
      data.is_valid_format?.value === false
    ) {

      return {
        valid:false,
        message:"Invalid email format"
      };
    }

    // =========================================
    // INVALID DOMAIN
    // =========================================

    if (
      data.is_mx_found?.value === false
    ) {

      return {
        valid:false,
        message:"Email domain invalid"
      };
    }

    // =========================================
    // BLOCK ONLY CLEARLY BAD EMAILS
    // =========================================

    if (
      data.deliverability === "UNDELIVERABLE"
    ) {

      return {
        valid:false,
        message:"Email inbox does not exist"
      };
    }

    // =========================================
    // ALLOW REAL + COMPANY EMAILS
    // =========================================

    return {
      valid:true
    };

  } catch (err) {

    console.log(
      "VALIDATION ERROR:",
      err.message
    );

    // =========================================
    // FAIL OPEN
    // DON'T BLOCK REAL USERS
    // =========================================

    return {
      valid:true
    };
  }
}

// ======================================================
// EMAIL TRANSPORT
// ======================================================

const transporter = nodemailer.createTransport({

  service:"gmail",

  auth:{
    user:EMAIL_USER,
    pass:EMAIL_PASS
  }
});

// ======================================================
// HOME
// ======================================================

app.get("/", (req,res)=>{

  res.json({
    success:true,
    message:"API Running 🚀"
  });

});

// ======================================================
// HEALTH
// ======================================================

app.get("/health", (req,res)=>{

  res.json({
    success:true
  });

});

// ======================================================
// SEND OTP
// ======================================================

app.post("/send-otp", async (req,res)=>{

  try {

    const { email } = req.body;

    // =========================================
    // EMAIL CHECK
    // =========================================

    if (
      !email ||
      !emailRegex.test(email)
    ) {

      return res.status(400).json({
        success:false,
        message:"Invalid email"
      });
    }

    // =========================================
    // COOLDOWN
    // =========================================

    const lastRequest =
      otpCooldown.get(email);

    if (
      lastRequest &&
      Date.now() - lastRequest < 60000
    ) {

      return res.status(429).json({
        success:false,
        message:"Wait 60 sec before retry"
      });
    }

    otpCooldown.set(
      email,
      Date.now()
    );

    // =========================================
    // VALIDATE EMAIL
    // =========================================

    const validation =
      await validateRealEmail(email);

    if (!validation.valid) {

      return res.status(400).json({
        success:false,
        message:validation.message
      });
    }

    // =========================================
    // GENERATE OTP
    // =========================================

    const otp = String(
      Math.floor(
        100000 + Math.random() * 900000
      )
    );

    const hashedOtp =
      await bcrypt.hash(otp,10);

    // =========================================
    // TOKEN
    // =========================================

    const vToken = jwt.sign(

      {
        email,
        otp:hashedOtp
      },

      JWT_SECRET,

      {
        expiresIn:"5m"
      }
    );

    // =========================================
    // SEND EMAIL
    // =========================================

    await transporter.sendMail({

      from:
`"Dawa Duniya" <${EMAIL_USER}>`,

      to:email,

      subject:"Your OTP Verification",

      html:`
      <div style="
        font-family:Poppins,sans-serif;
        padding:20px;
      ">

        <h2>
          Dawa Duniya OTP
        </h2>

        <h1 style="
          letter-spacing:5px;
          color:#00c896;
        ">
          ${otp}
        </h1>

        <p>
          OTP valid for 5 minutes
        </p>

      </div>
      `
    });

    return res.json({
      success:true,
      vToken
    });

  } catch (err) {

    console.log(
      "SEND OTP ERROR:",
      err
    );

    return res.status(500).json({
      success:false,
      message:"Server error"
    });
  }
});

// ======================================================
// VERIFY OTP
// ======================================================

app.post("/verify-otp", async (req,res)=>{

  try {

    const {
      userOtp,
      vToken
    } = req.body;

    if (
      !userOtp ||
      !vToken
    ) {

      return res.status(400).json({
        success:false,
        message:"Missing data"
      });
    }

    // =========================================
    // ATTEMPTS
    // =========================================

    const attempts =
      verifyAttempts.get(vToken) || 0;

    if (attempts >= 5) {

      return res.status(429).json({
        success:false,
        message:"Too many attempts"
      });
    }

    // =========================================
    // VERIFY JWT
    // =========================================

    let decoded;

    try {

      decoded = jwt.verify(
        vToken,
        JWT_SECRET
      );

    } catch {

      return res.status(400).json({
        success:false,
        message:"OTP expired"
      });
    }

    // =========================================
    // VERIFY OTP
    // =========================================

    const match =
      await bcrypt.compare(
        String(userOtp),
        decoded.otp
      );

    if (!match) {

      verifyAttempts.set(
        vToken,
        attempts + 1
      );

      return res.status(400).json({
        success:false,
        message:"Invalid OTP"
      });
    }

    // =========================================
    // LOGIN TOKEN
    // =========================================

    const loginToken = jwt.sign(

      {
        email:decoded.email
      },

      JWT_SECRET,

      {
        expiresIn:"1h"
      }
    );

    // =========================================
    // COOKIE
    // =========================================

    res.cookie(
      "dawaToken",
      loginToken,
      {
        httpOnly:true,
        secure:true,
        sameSite:"none",
        maxAge:3600000
      }
    );

    return res.json({
      success:true,
      token:loginToken
    });

  } catch (err) {

    console.log(
      "VERIFY OTP ERROR:",
      err
    );

    return res.status(500).json({
      success:false,
      message:"Verification failed"
    });
  }
});

// ======================================================
// SEND EMAIL LINK
// ======================================================

app.post("/send-link", async (req,res)=>{

  try {

    const { email } = req.body;

    if (!email) {

      return res.status(400).json({
        success:false,
        message:"Email required"
      });
    }

    // =========================================
    // VALIDATE EMAIL
    // =========================================

    const validation =
      await validateRealEmail(email);

    if (!validation.valid) {

      return res.status(400).json({
        success:false,
        message:validation.message
      });
    }

    // =========================================
    // TOKEN
    // =========================================

    const token = jwt.sign(

      { email },

      JWT_SECRET,

      {
        expiresIn:"10m"
      }
    );

    // =========================================
    // LINK
    // =========================================

    const link =
`${BASE_URL}/verify-email?token=${token}`;

    // =========================================
    // SEND EMAIL
    // =========================================

    await transporter.sendMail({

      from:
`"Dawa Duniya" <${EMAIL_USER}>`,

      to:email,

      subject:"Verify Your Email",

      html:`
      <div style="
        font-family:Poppins,sans-serif;
        padding:20px;
      ">

        <h2>
          Email Verification
        </h2>

        <p>
          Click below to verify email
        </p>

        <a
          href="${link}"
          style="
            display:inline-block;
            padding:12px 22px;
            background:#00c896;
            color:white;
            text-decoration:none;
            border-radius:10px;
            margin-top:12px;
          "
        >
          Verify Email
        </a>

      </div>
      `
    });

    return res.json({
      success:true
    });

  } catch (err) {

    console.log(
      "SEND LINK ERROR:",
      err
    );

    return res.status(500).json({
      success:false,
      message:"Server error"
    });
  }
});

// ======================================================
// VERIFY EMAIL LINK
// ======================================================

app.get("/verify-email", (req,res)=>{

  try {

    const { token } = req.query;

    if (!token) {

      return res.send(`
        <h2>
          Invalid verification link
        </h2>
      `);
    }

    // =========================================
    // VERIFY JWT
    // =========================================

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    // =========================================
    // LOGIN TOKEN
    // =========================================

    const loginToken = jwt.sign(

      {
        email:decoded.email
      },

      JWT_SECRET,

      {
        expiresIn:"1h"
      }
    );

    // =========================================
    // COOKIE
    // =========================================

    res.cookie(
      "dawaToken",
      loginToken,
      {
        httpOnly:true,
        secure:true,
        sameSite:"none",
        maxAge:3600000
      }
    );

    // =========================================
    // REDIRECT
    // =========================================

    return res.redirect(
      `${BASE_URL}/dashboard.html`
    );

  } catch (err) {

    console.log(
      "VERIFY LINK ERROR:",
      err
    );

    return res.send(`
      <h2>
        Invalid or expired link
      </h2>
    `);
  }
});

// ======================================================
// EXPORT
// ======================================================

module.exports = app;