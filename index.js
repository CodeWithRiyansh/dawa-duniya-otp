const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken'); // Sabse upar add karo
const JWT_SECRET = 'DawaDuniya_Super_Secret_Key_123'; // Ye aapka secret hai
require('dotenv').config();

const app = express();
app.use(express.json()); 
// Limiter setup: 5 minute mein sirf 3 baar OTP request
const otpLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, 
    max: 3, 
    message: { success: false, message: "Bhai, itni jaldi kya hai? 5 minute baad try karna!" },
    standardHeaders: true,
    legacyHeaders: false,
});

// 1. Static files ka access (Public folder se HTML/CSS load hogi)
app.use(express.static(path.join(__dirname, 'public')));

// 2. HOME ROUTE: Isse "Cannot GET /" wala error nahi aayega
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Transporter Setup (Gmail through Nodemailer)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

let otps = {}; 

// --- OTP BHEJNE KA ROUTE ---
app.post('/send-otp', otpLimiter, async (req, res) => {
    const { email } = req.body;

    // ... baaki logic (blacklist check etc) ...

    const otp = Math.floor(100000 + Math.random() * 900000);
    
    otps[email] = {
        code: otp,
        expiresAt: Date.now() + 5 * 60 * 1000 
    };

    // --- YE WALI LINE CHECK KARO (Isi mein galti hai) ---
    const mailOptions = {  // <--- Check karo yahan 'const' likha hai ya nahi
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Dawa Duniya OTP Verification',
        text: `Aapka OTP ye hai: ${otp}`
    };

    // Yahan mailOptions use ho raha hai, isliye upar define hona zaroori hai
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log("Mail Error:", error);
            return res.status(500).json({ success: false, message: "Email nahi gaya!" });
        }
        res.status(200).json({ success: true, message: "OTP sent successfully!" });
    });
});

    // Nodemailer with JSON Response
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log("Mail Error:", error.code);
            // Agar email exist nahi karti toh Nodemailer error dega
            if (error.code === 'EENVELOPE') {
                return res.status(400).json({ success: false, message: "Ye email exist nahi karti, check karein." });
            }
            return res.status(500).json({ success: false, message: "Email bhejte waqt error aaya!" });
        }
        // Success JSON
        res.status(200).json({ success: true, message: "OTP sent successfully!" });
    });


// --- OTP VERIFY KARNE KA ROUTE ---
app.post('/verify-otp', (req, res) => {
    const { email, userOtp } = req.body;
    const otpData = otps[email];

    if (otpData && otpData.code == userOtp && Date.now() < otpData.expiresAt) {
        delete otps[email];

        // 1. Token banao (User ki email aur secret use karke)
        // Ye token 1 ghante tak valid rahega
        const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });

        // 2. Token ko response mein bhejo
        res.status(200).json({ 
            success: true, 
            message: "Verified!", 
            token: token // Frontend ko token de diya
        });
    } else {
        res.status(400).json({ success: false, message: "Invalid or Expired OTP" });
    }
});