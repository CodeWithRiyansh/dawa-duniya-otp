const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path');
const jwt = require('jsonwebtoken');
const isDisposable = require('disposable-email-detector'); // Disposable detector
require('dotenv').config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'DawaDuniya_Noida_Secret_99';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Email validation Regex
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// SMTP Status Check
transporter.verify((error, success) => {
    if (error) console.log("❌ SMTP Error: " + error);
    else console.log("✅ SMTP Server Ready!");
});

// --- 1. OTP BHEJNE KA ROUTE ---
app.post('/send-otp', async (req, res) => {
    try {
        const { email } = req.body;

        // A. Format Validation (Regex)
        if (!email || !emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: "Bhai, sahi email format daalo!" });
        }

        // B. Disposable Email Check
        if (isDisposable(email)) {
            return res.status(400).json({ success: false, message: "Fake/Temporary emails allow nahi hain bhai!" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000);

        // OTP aur Email ko ek temp token mein pack kar do (5 min expiry)
        const vToken = jwt.sign({ email, otp }, JWT_SECRET, { expiresIn: '5m' });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Dawa Duniya OTP',
            text: `Aapka OTP hai: ${otp}. Ye 5 minute tak valid hai.`
        };

        // C. Send Success Check
        await transporter.sendMail(mailOptions);
        
        res.status(200).json({ success: true, vToken: vToken });
    } catch (err) {
        console.error("Mail Error:", err);
        res.status(500).json({ success: false, message: "Email bhenjne mein error aaya!" });
    }
});

// --- 2. VERIFY KARNE KA ROUTE ---
app.post('/verify-otp', (req, res) => {
    const { userOtp, vToken } = req.body;

    if (!vToken) return res.status(400).json({ success: false, message: "Session expired, dubara try karein!" });

    try {
        const decoded = jwt.verify(vToken, JWT_SECRET);

        if (decoded.otp == userOtp) {
            const loginToken = jwt.sign({ email: decoded.email }, JWT_SECRET, { expiresIn: '1h' });
            res.status(200).json({ success: true, token: loginToken });
        } else {
            res.status(400).json({ success: false, message: "Galat OTP hai bhai!" });
        }
    } catch (err) {
        res.status(400).json({ success: false, message: "OTP Expire ho gaya ya invalid hai!" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server Zinda Hai at port ${PORT}`));