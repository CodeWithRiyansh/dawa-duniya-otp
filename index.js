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

// --- MOTO BLOCK LIST (Common Temp Mail Domains) ---
const disposableDomains = [
    '10minutemail.com', 'tempmail.com', 'guerrillamail.com', 'mailinator.com', 'getnada.com',
    'dispostable.com', 'sharklasers.com', 'guerrillamailblock.com', 'guerrillamail.net',
    'guerrillamail.org', 'guerrillamail.biz', 'spam4.me', 'grr.la', 'pokemail.net',
    'vnet.ee', 'on0.biz', 'boximail.com', '0-mail.com', 'dropmail.me', 'yopmail.com',
    'temp-mail.org', 'internal.ml', 'luxusmail.xyz', 'outlook.guru', 'tempmail.net'
    // Aap isme aur bhi add kar sakte ho
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

app.post('/send-otp', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email || !emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: "Sahi email format daalo!" });
        }

        const domain = email.split('@')[1].toLowerCase();

        // 1. Exact Match Check
        // 2. Partial Match Check (Kayi baar subdomains hote hain)
        const isFake = disposableDomains.some(d => domain.includes(d));

        if (isFake) {
            console.log(`Blocked: ${email}`);
            return res.status(400).json({ success: false, message: "Bhai, ye temporary email yahan nahi chalega!" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000);
        const vToken = jwt.sign({ email, otp }, JWT_SECRET, { expiresIn: '5m' });

        await transporter.sendMail({
            from: `"Dawa Duniya" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Dawa Duniya OTP',
            text: `Aapka OTP hai: ${otp}`
        });

        res.status(200).json({ success: true, vToken });
    } catch (err) {
        console.error("Error:", err);
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
            res.status(400).json({ success: false, message: "Galat OTP!" });
        }
    } catch (err) {
        res.status(400).json({ success: false, message: "OTP Expire ho gaya!" });
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server on ${PORT}`));