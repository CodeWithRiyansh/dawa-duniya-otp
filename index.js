const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json()); 

// 1. Static files ka access (Public folder se HTML/CSS load hogi)
app.use(express.static(path.join(__dirname, 'public')));

// 2. HOME ROUTE: Isse "Cannot GET /" wala error nahi aayega
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Transporter Setup (Gmail through Nodemailer)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

let otps = {}; 

// --- OTP BHEJNE KA ROUTE ---
app.post('/send-otp', async (req, res) => {
    const { email } = req.body;

    // Domain Blocklist Check
    const blacklistedDomains = ['tempmail.com', '10minutemail.com', 'mailinator.com'];
    const domain = email.split('@')[1];
    if (blacklistedDomains.includes(domain)) {
        return res.status(400).json({ success: false, message: "Bhai, ye temporary email allow nahi hai!" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);
    otps[email] = otp;

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Dawa Duniya OTP Verification',
        text: `Aapka OTP ye hai: ${otp}`
    };

    // Nodemailer with JSON Response
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log("Mail Error:", error.code);
            // Agar email exist nahi karti toh Nodemailer error dega
            if (error.code === 'EENVELOPE') {
                return res.status(400).json({ success: false, message: "Ye email exist nahi karti, check karein." });
            }
            return res.status(500).json({ success: false, message: "Email bhejte waqt error aaya!" });
        }
        // Success JSON
        res.status(200).json({ success: true, message: "OTP sent successfully!" });
    });
});

// --- OTP VERIFY KARNE KA ROUTE ---
app.post('/verify-otp', (req, res) => {
    const { email, userOtp } = req.body;
    
    if (otps[email] && otps[email] == userOtp) {
        delete otps[email];
        // Redirect logic ke liye JSON success bhejna zaroori hai
        res.status(200).json({ success: true, message: "Verification Successful!" });
    } else {
        res.status(400).json({ success: false, message: "Galat OTP hai bhai!" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});