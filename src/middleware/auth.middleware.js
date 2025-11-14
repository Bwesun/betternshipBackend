const jwt = require('jsonwebtoken');

// Middleware to protect routes
const protect = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    // console.log(authHeader);

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      // console.error('Not authorized, no token');
      return res.status(401).json({ message: 'Not authorized, no token' });
    }

    const token = authHeader.split(' ')[1];

    if (!token || token.split('.').length !== 3) {
      // console.error('Malformed token');
      return res.status(400).json({ message: 'Malformed token' });
    }

    if (!process.env.JWT_SECRET) {
      // console.error('JWT_SECRET not set');
      return res.status(500).json({ message: 'Server configuration error' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    next();
  } catch (error) {
    console.error('Token verification error:', error.message);
    return res.status(401).json({ message: 'Not authorized, token failed', error: error.message });
  }
};


// Middleware to authorize based on user roles
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Not authorized' });
    }

    // if no roles provided, allow any authenticated user
    if (roles.length === 0) {
      return next();
    }

    // allow when user role matches one of the required roles
    if (roles.includes(req.user.role)) {
      return next();
    }

    // otherwise deny
    return res.status(403).json({
      message: 'Access denied',
      requiredRoles: roles,
      userRole: req.user.role
    });
  };
};

module.exports = {
  protect,
  authorize,
};
