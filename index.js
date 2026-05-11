const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'DawaDuniya_Noida_Secret_99';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// --- 1. OTP BHEJNE KA ROUTE ---
app.post('/send-otp', async (req, res) => {
    try {
        const { email } = req.body;
        const otp = Math.floor(100000 + Math.random() * 900000);

        // OTP aur Email ko ek temp token mein pack kar do (5 min expiry)
        const vToken = jwt.sign({ email, otp }, JWT_SECRET, { expiresIn: '5m' });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Dawa Duniya OTP',
            text: `Aapka OTP hai: ${otp}`
        };

        await transporter.sendMail(mailOptions);
        
        // Token ko frontend ko bhej do
        res.status(200).json({ success: true, vToken: vToken });
    } catch (err) {
        res.status(500).json({ success: false, message: "Email failed!" });
    }
});

// --- 2. VERIFY KARNE KA ROUTE ---
app.post('/verify-otp', (req, res) => {
    const { userOtp, vToken } = req.body;

    try {
        // Token ko khol kar dekho
        const decoded = jwt.verify(vToken, JWT_SECRET);

        if (decoded.otp == userOtp) {
            // Success! Login token banao
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
app.listen(PORT, () => console.log(`Server Zinda Hai!`));