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

// Manual Disposable List (No library needed)
const disposableDomains = ['10minutemail.com', 'tempmail.com', 'guerrillamail.com', 'mailinator.com'];

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
            return res.status(400).json({ success: false, message: "Sahi email format daalo!" });
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

// ✅ FIX: '*' ko '(.*)' kar diya hai taaki Express crash na ho
app.get('(.*)', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server on ${PORT}`));