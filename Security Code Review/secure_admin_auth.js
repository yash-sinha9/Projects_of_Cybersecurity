/* Secure Express Backend Authentication & Access Control Middleware (secure_admin_auth.js) */

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'super-secure-key-change-in-production';

// In-memory or database user representation
const adminUser = {
  username: 'admin',
  passwordHash: '$2a$12$N9qo8uLOqp.Z7o24S7bWdO3bK0V7tX3gH/Z/6s8xU1vXw.e7f8M3C' // example hash for 'secure_password_123'
};

/**
 * Access Control Middleware
 * Verifies the JSON Web Token (JWT) sent in HTTP headers or HTTP-Only cookies.
 */
function requireAdminAuth(req, res, next) {
  // Extract token from HTTP-only cookie or Authorization header
  const token = req.cookies.admin_session || req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      error: "Authentication Required",
      message: "Access denied. Please sign in as an administrator."
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({
        error: "Access Denied",
        message: "Forbidden. Administrative privileges required."
      });
    }
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({
      error: "Invalid Token",
      message: "Your session has expired or is invalid. Please log in again."
    });
  }
}

/**
 * Admin Login Endpoint
 * Validates credentials and returns a secure HTTP-Only cookie.
 */
router.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Missing username or password" });
  }

  try {
    if (username !== adminUser.username) {
      return res.status(401).json({ error: "Invalid administrative credentials" });
    }

    const isMatch = await bcrypt.compare(password, adminUser.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid administrative credentials" });
    }

    // Sign jwt token
    const token = jwt.sign(
      { username: adminUser.username, role: 'admin' },
      JWT_SECRET,
      { expiresIn: '2h' }
    );

    // Set secure HttpOnly cookie to defend against XSS reading tokens
    res.cookie('admin_session', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // true in production (HTTPS only)
      sameSite: 'strict',
      maxAge: 2 * 60 * 60 * 1000 // 2 hours
    });

    return res.json({ success: true, message: "Logged in successfully" });
  } catch (error) {
    console.error("Login Error:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

module.exports = {
  adminAuthRouter: router,
  requireAdminAuth
};
