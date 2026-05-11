const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path'); // Ye line zaroori hai
require('dotenv').config();

const app = express();
app.use(express.json()); 

// 1. Static files ka access (Isse CSS aur Images load hongi)
app.use(express.static(path.join(__dirname, 'public')));

// 2. HOME ROUTE: Isse "Cannot GET /" wala error khatam ho jayega
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Transporter Setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

let otps = {}; 

// OTP Bhejne ka Route
app.post('/send-otp', (req, res) => {
    const { email } = req.body;
    const otp = Math.floor(100000 + Math.random() * 900000);
    otps[email] = otp;

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Dawa Duniya OTP',
        text: `Bhai, aapka OTP ye hai: ${otp}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) return res.status(500).send("Email nahi gaya!");
        res.status(200).send("OTP bhej diya gaya!");
    });
});

// OTP Verify karne ka Route
app.post('/verify-otp', (req, res) => {
    const { email, userOtp } = req.body;
    if (otps[email] && otps[email] == userOtp) {
        delete otps[email];
        res.status(200).send("Success");
    } else {
        res.status(400).send("Wrong OTP");
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});