const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'DawaDuniya_Noida_Secret_99';

// Body parser
app.use(express.json());

// Static files serve karne ke liye
app.use(express.static(path.join(__dirname, 'public')));

// Email validation Regex
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Manual Disposable List (Saare bad domains block karne ke liye)
const disposableDomains = ['10minutemail.com', 'tempmail.com', 'guerrillamail.com', 'mailinator.com', 'getnada.com'];

// SMTP Config
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true, 
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// --- ROUTES ---

// 1. OTP BHEJNE KA ROUTE
app.post('/send-otp', async (req, res) => {
    try {
        const { email } = req.body;

        // Validation
        if (!email || !emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: "Sahi email format daalo bhai!" });
        }

        const domain = email.split('@')[1].toLowerCase();
        if (disposableDomains.includes(domain)) {
            return res.status(400).json({ success: false, message: "Fake email allowed nahi hai!" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000);
        const vToken = jwt.sign({ email, otp }, JWT_SECRET, { expiresIn: '5m' });

        await transporter.sendMail({
            from: `"Dawa Duniya" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Dawa Duniya OTP',
            text: `Aapka OTP hai: ${otp}. Ye 5 min mein expire ho jayega.`
        });

        res.status(200).json({ success: true, vToken });
    } catch (err) {
        console.error("Vercel Mail Error:", err);
        res.status(500).json({ success: false, message: "Email bhenjne mein error aaya!" });
    }
});

// 2. VERIFY KARNE KA ROUTE
app.post('/verify-otp', (req, res) => {
    const { userOtp, vToken } = req.body;
    try {
        const decoded = jwt.verify(vToken, JWT_SECRET);
        if (decoded.otp == userOtp) {
            const loginToken = jwt.sign({ email: decoded.email }, JWT_SECRET, { expiresIn: '1h' });
            res.status(200).json({ success: true, token: loginToken });
        } else {
            res.status(400).json({ success: false, message: "Galat OTP hai!" });
        }
    } catch (err) {
        res.status(400).json({ success: false, message: "OTP Expire ho gaya!" });
    }
});

// ✅ FIX: Wildcard route ko hatakar simple index.html serve kar rahe hain
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Dawa Duniya live on ${PORT}`));