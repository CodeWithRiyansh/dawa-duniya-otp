const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path');
const jwt = require('jsonwebtoken');
const { isDisposable } = require('disposable-email-detector'); // Fixed Import ✅
require('dotenv').config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'DawaDuniya_Noida_Secret_99';

// 1. Middleware for JSON and Static Files
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // Frontend files (index.html, etc.) serve karne ke liye

// 2. Email validation Regex
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// 3. SMTP Configuration (Vercel-Friendly) ✅
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true, // SSL for security
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS // Gmail App Password zaroori hai
    }
});

// SMTP Status Check on Startup
transporter.verify((error, success) => {
    if (error) console.log("❌ SMTP Connection Error: " + error);
    else console.log("✅ SMTP Server Ready to send mails!");
});

// --- ROUTES ---

// A. OTP BHEJNE KA ROUTE
app.post('/send-otp', async (req, res) => {
    try {
        const { email } = req.body;

        // Validation 1: Format Check
        if (!email || !emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: "Bhai, sahi email format daalo!" });
        }

        // Validation 2: Disposable Email Check ✅
        if (isDisposable(email)) {
            console.log(`Blocked disposable email attempt: ${email}`);
            return res.status(400).json({ success: false, message: "Fake/Temporary email allowed nahi hai!" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000);

        // JWT token with email and otp (5 min expiry)
        const vToken = jwt.sign({ email, otp }, JWT_SECRET, { expiresIn: '5m' });

        const mailOptions = {
            from: `"Dawa Duniya Admin" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Dawa Duniya Login OTP',
            html: `<h3>Welcome to Dawa Duniya!</h3><p>Aapka OTP hai: <b>${otp}</b></p><p>Ye OTP sirf 5 minute ke liye valid hai.</p>`
        };

        // Send Success Check
        await transporter.sendMail(mailOptions);
        console.log(`OTP sent to: ${email}`);
        
        res.status(200).json({ success: true, vToken: vToken });
    } catch (err) {
        console.error("Mail Error:", err);
        res.status(500).json({ success: false, message: "Email bhenjne mein error aaya! Check SMTP Logs." });
    }
});

// B. VERIFY KARNE KA ROUTE
app.post('/verify-otp', (req, res) => {
    const { userOtp, vToken } = req.body;

    if (!vToken) return res.status(400).json({ success: false, message: "Session expired!" });

    try {
        const decoded = jwt.verify(vToken, JWT_SECRET);

        if (decoded.otp == userOtp) {
            // Login success token (1 hour valid)
            const loginToken = jwt.sign({ email: decoded.email }, JWT_SECRET, { expiresIn: '1h' });
            res.status(200).json({ success: true, token: loginToken });
        } else {
            res.status(400).json({ success: false, message: "Galat OTP hai bhai!" });
        }
    } catch (err) {
        res.status(400).json({ success: false, message: "OTP Expire ho gaya ya invalid hai!" });
    }
});

// C. Serve index.html as fallback
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Dawa Duniya Server Zinda Hai at port ${PORT}`));