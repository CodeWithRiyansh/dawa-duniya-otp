const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'DawaDuniya_Noida_Secret_99';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// --- CUSTOM DISPOSABLE BLOCKER ---
// Hum khud ki list maintain karenge taaki library crash na kare
const disposableDomains = [
    '10minutemail.com', 'tempmail.com', 'guerrillamail.com', 'sharklasers.com', 
    'mailinator.com', 'dispostable.com', 'getnada.com', 'boun.cr'
];

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

app.post('/send-otp', async (req, res) => {
    try {
        const { email } = req.body;

        // 1. Format Check
        if (!email || !emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: "Bhai, sahi email format daalo!" });
        }

        // 2. Manual Disposable Check (No library needed now) ✅
        const domain = email.split('@')[1].toLowerCase();
        if (disposableDomains.includes(domain)) {
            return res.status(400).json({ success: false, message: "Fake email allowed nahi hai!" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000);
        const vToken = jwt.sign({ email, otp }, JWT_SECRET, { expiresIn: '5m' });

        const mailOptions = {
            from: `"Dawa Duniya" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Dawa Duniya OTP',
            text: `Aapka OTP hai: ${otp}`
        };

        await transporter.sendMail(mailOptions);
        res.status(200).json({ success: true, vToken: vToken });
    } catch (err) {
        console.error("Final Error Log:", err);
        res.status(500).json({ success: false, message: "Email bhenjne mein error aaya!" });
    }
});

app.post('/verify-otp', (req, res) => {
    const { userOtp, vToken } = req.body;
    try {
        const decoded = jwt.verify(vToken, JWT_SECRET);
        if (decoded.otp == userOtp) {
            const loginToken = jwt.sign({ email: decoded.email }, JWT_SECRET, { expiresIn: '1h' });
            res.status(200).json({ success: true, token: loginToken });
        } else {
            res.status(400).json({ success: false, message: "Galat OTP hai bhai!" });
        }
    } catch (err) {
        res.status(400).json({ success: false, message: "OTP Expire ho gaya!" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server Running!`));