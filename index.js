const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path');
const jwt = require('jsonwebtoken');
const axios = require('axios'); // Naya domains check karne ke liye
require('dotenv').config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'DawaDuniya_Noida_Secret_99';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

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

        // --- REAL-TIME CHECK (FOR NEW TEMP MAILS) ---
        const domain = email.split('@')[1].toLowerCase();
        
        try {
            // Hum ek public list se check kar rahe hain jo daily update hoti hai
            const response = await axios.get(`https://open.kickbox.com/v1/disposable/${domain}`);
            
            if (response.data.disposable === true) {
                console.log(`Blocked Dynamic Temp Mail: ${email}`);
                return res.status(400).json({ success: false, message: "Bhai, ye temporary email nahi chalega!" });
            }
        } catch (apiErr) {
            // Agar API down ho, toh code crash na ho, isliye backup list check karein
            const backupList = ['gcervera.com', '10minutemail.com', 'tempmail.com'];
            if (backupList.includes(domain)) {
                return res.status(400).json({ success: false, message: "Fake email blocked!" });
            }
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

// ... Baki code (verify-otp aur get route) same rahega ...

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
app.listen(PORT, () => console.log(`🚀 Dawa Duniya Secure on ${PORT}`));