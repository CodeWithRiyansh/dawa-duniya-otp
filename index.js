const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'DawaDuniya_Noida_Secret_99';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// 1. Sirf in domains ko allow karenge
const allowedDomains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'rediffmail.com', 'protonmail.com'];

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

        if (!email || !emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: "Sahi email format daalo bhai!" });
        }

        const domain = email.split('@')[1].toLowerCase();

        // ✅ STEP 1: Strict Whitelist Check
        // Agar domain allowed list mein nahi hai (jaise gcervera.com), toh yahi se block.
        if (!allowedDomains.includes(domain)) {
            console.log(`Blocked Unlisted Domain: ${domain}`);
            return res.status(400).json({ success: false, message: "Sirf Gmail, Yahoo ya Outlook hi chalega!" });
        }

        // ✅ STEP 2: Real-time API Check (Backup Security)
        try {
            const response = await axios.get(`https://open.kickbox.com/v1/disposable/${domain}`);
            if (response.data.disposable === true) {
                return res.status(400).json({ success: false, message: "Temporary email allowed nahi hai!" });
            }
        } catch (apiErr) {
            console.log("API check skipped, relying on whitelist.");
        }

        const otp = Math.floor(100000 + Math.random() * 900000);
        const vToken = jwt.sign({ email, otp }, JWT_SECRET, { expiresIn: '5m' });

        await transporter.sendMail({
            from: `"Dawa Duniya" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Dawa Duniya Login OTP',
            text: `Aapka OTP hai: ${otp}. Ye 5 min tak valid hai.`
        });

        res.status(200).json({ success: true, vToken });
    } catch (err) {
        console.error("Mail Error:", err);
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
            res.status(400).json({ success: false, message: "Galat OTP hai!" });
        }
    } catch (err) {
        res.status(400).json({ success: false, message: "OTP Expire ho gaya!" });
    }
});

// ✅ FIX: Vercel PathError se bachne ke liye standard fallback
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Dawa Duniya Secure on ${PORT}`));