const { body } = require('express-validator');

const registerValidation = () => {
  return [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Invalid email format'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    body('role').isIn(['staff', 'user', 'admin']).withMessage('Invalid role'),
  ];
};

const loginValidation = () => {
  return [
    body('email').isEmail().withMessage('Invalid email format'),
    body('password').notEmpty().withMessage('Password is required'),
  ];
};

module.exports = {
  registerValidation,
  loginValidation,
};
