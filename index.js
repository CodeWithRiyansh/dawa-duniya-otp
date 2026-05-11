const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'DawaDuniya_Super_Secret_Key_123';

// 1. Rate Limiter: Spam rokne ke liye
const otpLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, 
    max: 5, // Ek user 5 min mein 5 baar OTP mangwa sakta hai
    message: { success: false, message: "Bhai, itni jaldi kya hai? 5 minute baad try karna!" },
    standardHeaders: true,
    legacyHeaders: false,
});

// 2. Static files & Home Route
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 3. Nodemailer Transporter Setup
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
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ success: false, message: "Email zaroori hai bhai!" });
        }

        // Domain Check
        const blacklistedDomains = ['tempmail.com', '10minutemail.com', 'mailinator.com'];
        const domain = email.split('@')[1];
        if (blacklistedDomains.includes(domain)) {
            return res.status(400).json({ success: false, message: "Bhai, ye temporary email allow nahi hai!" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000);
        
        // Save OTP with 5 min Expiry
        otps[email] = {
            code: otp,
            expiresAt: Date.now() + 5 * 60 * 1000 
        };

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Dawa Duniya OTP Verification',
            text: `Aapka OTP ye hai: ${otp}. Ye sirf 5 minute ke liye valid hai.`
        };

        // SIRF EK BAAR SENDMAIL CALL KARNA HAI
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log("Mail Error:", error);
                return res.status(500).json({ success: false, message: "Email bhejte waqt error aaya!" });
            }
            res.status(200).json({ success: true, message: "OTP sent successfully!" });
        });

    } catch (err) {
        console.error("Internal Error:", err);
        res.status(500).json({ success: false, message: "Server crash ho raha hai!" });
    }
});

// --- OTP VERIFY KARNE KA ROUTE ---
app.post('/verify-otp', (req, res) => {
    const { email, userOtp } = req.body;
    const otpData = otps[email];

    // Check if OTP exists, matches and not expired
    if (otpData && otpData.code == userOtp) {
        
        if (Date.now() > otpData.expiresAt) {
            delete otps[email];
            return res.status(400).json({ success: false, message: "Bhai, OTP expire ho gaya hai!" });
        }

        delete otps[email]; // Clear OTP after success

        // JWT Token pass generate karna
        const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ 
            success: true, 
            message: "Verified!", 
            token: token 
        });
    } else {
        res.status(400).json({ success: false, message: "Galat OTP hai bhai!" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));