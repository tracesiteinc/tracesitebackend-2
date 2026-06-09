const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const { userQueries } = require('../db/database');
const { authenticate } = require('../middleware/auth');

// ─────────────────────────────────────────────
//  POST /api/auth/register
// ─────────────────────────────────────────────
router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: 'Name, email, and password are required.' });
    }
    if (!validator.isEmail(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email address.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters.' });
    }

    // Check if email already exists
    const existing = userQueries.findByEmail.get(email.toLowerCase());
    if (existing) {
      return res.status(409).json({ success: false, message: 'An account with this email already exists.' });
    }

    // Hash password
    const hashed = await bcrypt.hash(password, 12);

    // Determine role (first user becomes admin)
    const isFirstUser = !userQueries.findByEmail.get(process.env.ADMIN_EMAIL);
    const role = (email.toLowerCase() === process.env.ADMIN_EMAIL?.toLowerCase()) ? 'admin' : 'user';

    // Insert user
    const result = userQueries.create.run({
      name:     name.trim(),
      email:    email.toLowerCase().trim(),
      password: hashed,
      role,
    });

    // Sign JWT
    const token = jwt.sign(
      { id: result.lastInsertRowid, role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    return res.status(201).json({
      success: true,
      message: 'Account created successfully.',
      token,
      user: {
        id:    result.lastInsertRowid,
        name:  name.trim(),
        email: email.toLowerCase().trim(),
        role,
      },
    });
  } catch (err) {
    console.error('[AUTH] Register error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
  }
});

// ─────────────────────────────────────────────
//  POST /api/auth/login
// ─────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }

    const user = userQueries.findByEmail.get(email.toLowerCase().trim());
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    const { password: _, ...safeUser } = user;

    return res.json({
      success: true,
      message: 'Login successful.',
      token,
      user: safeUser,
    });
  } catch (err) {
    console.error('[AUTH] Login error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
  }
});

// ─────────────────────────────────────────────
//  GET /api/auth/me  (protected)
// ─────────────────────────────────────────────
router.get('/me', authenticate, (req, res) => {
  return res.json({ success: true, user: req.user });
});

module.exports = router;
