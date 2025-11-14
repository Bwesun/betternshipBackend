const express = require('express');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { Pool } = require('pg');

const router = express.Router();
const { register, login, authMe } = require('./auth.controller');
const { validate } = require('../../middleware/validation');
const { registerValidation, loginValidation } = require('../../middleware/validators');
const { protect, authorize } = require('../../middleware/auth.middleware');


router.post('/register', registerValidation(), validate, register);
router.post('/login', loginValidation(), validate, login);
router.get('/me', protect, authMe);

// ----------RESET PASSWORD ROUTES------------
// Create a connection pool
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  max: 100, // Maximum number of clients in the pool
  idleTimeoutMillis: 30000, // Close idle clients after 30 seconds
  connectionTimeoutMillis: 8000, // Return an error after 8 seconds if connection could not be established
});


const OTP_EXPIRES_MINUTES = parseInt(process.env.OTP_EXPIRES_MINUTES || '10', 10);
const OTP_RESEND_WAIT_SECONDS = parseInt(process.env.OTP_RESEND_WAIT_SECONDS || '60', 10);

const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '3', 10);
const RATE_LIMIT_WINDOW_MIN = parseInt(process.env.RATE_LIMIT_WINDOW_MIN || '30', 10);

// Rate limiter for OTP requests (per IP)
const otpLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MIN * 60 * 1000,
  max: RATE_LIMIT_MAX,
  message: { message: 'Too many OTP requests. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// create nodemailer transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

/**
 * Helper: hash OTP (sha256 hex)
 */
function hashOtp(otp) {
  return crypto.createHash('sha256').update(otp).digest('hex');
}

/**
 * POST /request-reset
 * Request an OTP be sent to email. (Rate-limited)
 * Response intentionally generic to avoid email enumeration.
 */
router.post('/request-reset', otpLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email required' });

  try {
    const userRes = await pool.query('SELECT id FROM users WHERE email = $1', [email]);

    // Always return generic message to the client
    const genericResponse = { message: 'If your email exists, an OTP has been sent.' };

    if (userRes.rows.length === 0) {
      // Do not reveal email does not exist
      return res.json(genericResponse);
    }

    const userId = userRes.rows[0].id;

    // Delete any existing OTPs for that user (prevent multiple valid OTPs)
    await pool.query('DELETE FROM password_resets WHERE user_id = $1', [userId]);

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit
    const otpHash = hashOtp(otp);
    const expiresAt = new Date(Date.now() + OTP_EXPIRES_MINUTES * 60 * 1000);

    // Insert hashed OTP
    await pool.query(
      'INSERT INTO password_resets (user_id, otp_hash, expires_at) VALUES ($1, $2, $3)',
      [userId, otpHash, expiresAt]
    );

    // Send OTP via email (asynchronously; don't send OTP in response)
    const mailHtml = `
      <p>You requested a password reset. Use the 6-digit code below to reset your password:</p>
      <h2>${otp}</h2>
      <p>This code expires in ${OTP_EXPIRES_MINUTES} minutes.</p>
      <p>If you didn't request this, ignore this message.</p>
    `;

    transporter.sendMail({
      from: `"Agribusiness Cluster App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Password Reset OTP',
      html: mailHtml,
    }).catch(err => {
      // log error but don't expose to user
      console.error('Error sending OTP email:', err);
    });

    return res.json(genericResponse);
  } catch (err) {
    console.error('request-reset error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
});

/**
 * POST /verify-otp
 * Verify the OTP sent to email.
 * Body: { email, otp }
 */
router.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ message: 'Email and OTP are required' });

  try {
    const userRes = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userRes.rows.length === 0) return res.status(400).json({ message: 'Invalid OTP or email' });

    const userId = userRes.rows[0].id;

    // Get latest OTP record
    const otpRows = await pool.query(
      'SELECT id, otp_hash, expires_at, verified FROM password_resets WHERE user_id = $1 ORDER BY id DESC LIMIT 1',
      [userId]
    );
    if (otpRows.rows.length === 0) return res.status(400).json({ message: 'Invalid OTP or email' });

    const record = otpRows.rows[0];

    // Check expiry
    if (new Date(record.expires_at) < new Date()) {
      // remove expired record
      await pool.query('DELETE FROM password_resets WHERE id = $1', [record.id]);
      return res.status(400).json({ message: 'OTP expired' });
    }

    // compare hashed OTPs
    const inputHash = hashOtp(String(otp));
    if (inputHash !== record.otp_hash) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    // Mark OTP as verified and expire it immediately (so it can't be reused)
    await pool.query('UPDATE password_resets SET verified = TRUE, expires_at = NOW() WHERE id = $1', [record.id]);

    return res.json({ message: 'OTP verified successfully' });
  } catch (err) {
    console.error('verify-otp error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
});

/**
 * POST /reset-password
 * Reset password after OTP verified.
 * Body: { email, password }
 */
router.post('/reset-password', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email and password are required' });

  try {
    const userRes = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userRes.rows.length === 0) return res.status(404).json({ message: 'User not found' });

    const userId = userRes.rows[0].id;

    // Ensure there is a recently verified OTP for this user
    const verifiedRows = await pool.query(
      'SELECT id FROM password_resets WHERE user_id = $1 AND verified = TRUE ORDER BY id DESC LIMIT 1',
      [userId]
    );

    if (verifiedRows.rows.length === 0) {
      return res.status(400).json({ message: 'OTP not verified or expired' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update user password
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, userId]);

    // Cleanup all OTP records for this user
    await pool.query('DELETE FROM password_resets WHERE user_id = $1', [userId]);

    // Notify user via email about password change
    const mailHtml = `
      <p>Your password was changed successfully. If you did not perform this action, contact support immediately.</p>
    `;
    transporter.sendMail({
      from: `"Agribusiness Cluster App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Password Changed',
      html: mailHtml,
    }).catch(err => console.error('Error sending password change email:', err));

    return res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('reset-password error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
