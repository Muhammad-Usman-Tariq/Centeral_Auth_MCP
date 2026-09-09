const rateLimit = require('express-rate-limit');
const config = require('../config');

const tokenLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'slow_down',
    error_description: 'Too many token requests, please try again later.'
  }
});

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30, // 30 registrations per 15 minutes
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'slow_down',
    error_description: 'Too many client registrations, please try again later.'
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'slow_down',
    error_description: 'Too many authentication attempts, please try again later.'
  }
});

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // 10 login attempts per 15 minutes to prevent brute force
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many login attempts. Account temporarily throttled for 15 minutes.'
  }
});

module.exports = {
  tokenLimiter,
  registerLimiter,
  authLimiter,
  adminLoginLimiter
};
