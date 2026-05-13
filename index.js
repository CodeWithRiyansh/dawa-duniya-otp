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

const {
  JWT_SECRET,
  EMAIL_USER,
  EMAIL_PASS,
  ABSTRACT_API_KEY,
  BASE_URL
} = process.env;

// ======================================================
// SECURITY
// ======================================================

app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

app.use(
  cors({
    origin: true,
    credentials: true
  })
);

app.use(express.json());
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
    message: "Too many requests"
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
  "maildrop.cc"
];

async function validateRealEmail(email) {

  try {

    const domain =
      email.split("@")[1]?.toLowerCase();

    // BLOCK TEMP DOMAINS
    if (blockedDomains.includes(domain)) {

      return {
        valid:false,
        message:"Temporary email not allowed"
      };
    }

    const response = await axios.get(
      `https://emailvalidation.abstractapi.com/v1/?api_key=${ABSTRACT_API_KEY}&email=${email}`
    );

    const data = response.data;

    // TEMP EMAIL BLOCK
    if (
      data.is_disposable_email &&
      data.is_disposable_email.value === true
    ) {

      return {
        valid:false,
        message:"Temporary email not allowed"
      };
    }

    // FORMAT CHECK
    if (
      data.is_valid_format &&
      data.is_valid_format.value === false
    ) {

      return {
        valid:false,
        message:"Invalid email format"
      };
    }

    // MX CHECK
    if (
      data.is_mx_found &&
      data.is_mx_found.value === false
    ) {

      return {
        valid:false,
        message:"Domain cannot receive emails"
      };
    }

    // SMTP CHECK
    if (
      data.is_smtp_valid &&
      data.is_smtp_valid.value === false
    ) {

      return {
        valid:false,
        message:"Email inbox does not exist"
      };
    }

    return {
      valid:true
    };

  } catch (err) {

    console.log("VALIDATION ERROR:", err.message);

    return {
      valid:true
    };
  }
}
    // DELIVERABILITY
    // ONLY BLOCK CLEARLY FAKE EMAILS

if (
  data.is_smtp_valid &&
  data.is_smtp_valid.value === false
) {

  return {
    valid:false,
    message:"Email inbox does not exist"
  };
}

    return {
      valid:true
    };

  } catch (err) {

    console.log("VALIDATION ERROR:", err.message);

    return {
      valid:false,
      message:"Email validation failed"
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

  try{

    const { email } = req.body;

    if(!email || !emailRegex.test(email)){

      return res.status(400).json({
        success:false,
        message:"Invalid email"
      });
    }

    // COOLDOWN
    const lastRequest =
      otpCooldown.get(email);

    if(
      lastRequest &&
      Date.now() - lastRequest < 60000
    ){

      return res.status(429).json({
        success:false,
        message:"Wait 60 sec before retry"
      });
    }

    otpCooldown.set(email, Date.now());

    // VALIDATE EMAIL
    const validation =
      await validateRealEmail(email);

    if(!validation.valid){

      return res.status(400).json({
        success:false,
        message:validation.message
      });
    }

    // OTP
    const otp =
      String(
        Math.floor(
          100000 + Math.random() * 900000
        )
      );

    const hashedOtp =
      await bcrypt.hash(otp,10);

    // TOKEN
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

    // SEND EMAIL
    await transporter.sendMail({

      from:`"Dawa Duniya" <${EMAIL_USER}>`,

      to:email,

      subject:"Your OTP Verification",

      html:`
      <div style="font-family:Poppins,sans-serif;padding:20px;">

        <h2>Dawa Duniya OTP</h2>

        <h1 style="letter-spacing:4px;">
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

  }catch(err){

    console.log("SEND OTP ERROR:", err);

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

  try{

    const { userOtp, vToken } = req.body;

    if(!userOtp || !vToken){

      return res.status(400).json({
        success:false,
        message:"Missing data"
      });
    }

    // VERIFY ATTEMPTS
    const attempts =
      verifyAttempts.get(vToken) || 0;

    if(attempts >= 5){

      return res.status(429).json({
        success:false,
        message:"Too many attempts"
      });
    }

    let decoded;

    try{

      decoded =
        jwt.verify(vToken, JWT_SECRET);

    }catch{

      return res.status(400).json({
        success:false,
        message:"OTP expired"
      });
    }

    // OTP MATCH
    const match =
      await bcrypt.compare(
        String(userOtp),
        decoded.otp
      );

    if(!match){

      verifyAttempts.set(
        vToken,
        attempts + 1
      );

      return res.status(400).json({
        success:false,
        message:"Invalid OTP"
      });
    }

    // LOGIN TOKEN
    const loginToken = jwt.sign(
      {
        email:decoded.email
      },
      JWT_SECRET,
      {
        expiresIn:"1h"
      }
    );

    // COOKIE
    res.cookie("dawaToken", loginToken, {
      httpOnly:true,
      secure:true,
      sameSite:"none",
      maxAge:3600000
    });

    return res.json({
      success:true,
      token:loginToken
    });

  }catch(err){

    console.log("VERIFY OTP ERROR:", err);

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

  try{

    const { email } = req.body;

    if(!email){

      return res.status(400).json({
        success:false,
        message:"Email required"
      });
    }

    const validation =
      await validateRealEmail(email);

    if(!validation.valid){

      return res.status(400).json({
        success:false,
        message:validation.message
      });
    }

    const token = jwt.sign(
      { email },
      JWT_SECRET,
      {
        expiresIn:"10m"
      }
    );

    const link =
`${BASE_URL}/verify-email?token=${token}`;

    await transporter.sendMail({

      from:`"Dawa Duniya" <${EMAIL_USER}>`,

      to:email,

      subject:"Verify Your Email",

      html:`
      <div style="font-family:Poppins,sans-serif;padding:20px;">

        <h2>Email Verification</h2>

        <p>
          Click button below to verify email
        </p>

        <a
          href="${link}"
          style="
            display:inline-block;
            padding:12px 20px;
            background:#00c896;
            color:white;
            text-decoration:none;
            border-radius:10px;
            margin-top:10px;
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

  }catch(err){

    console.log("SEND LINK ERROR:", err);

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

  try{

    const { token } = req.query;

    if(!token){

      return res.send(`
        <h2>Invalid verification link</h2>
      `);
    }

    const decoded =
      jwt.verify(token, JWT_SECRET);

    const loginToken = jwt.sign(
      {
        email:decoded.email
      },
      JWT_SECRET,
      {
        expiresIn:"1h"
      }
    );

    res.cookie("dawaToken", loginToken, {
      httpOnly:true,
      secure:true,
      sameSite:"none",
      maxAge:3600000
    });

    return res.redirect(
      `${BASE_URL}/dashboard.html`
    );

  }catch(err){

    console.log("VERIFY LINK ERROR:", err);

    return res.send(`
      <h2>Invalid or expired link</h2>
    `);
  }
});

// ======================================================
// EXPORT
// ======================================================

module.exports = app;