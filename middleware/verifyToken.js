const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) {
        return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });
    }

    try {
        const tokenString = token.startsWith('Bearer ') ? token.slice(7) : token;
        const verified = jwt.verify(tokenString, process.env.JWT_SECRET);
        console.log('Token verified:', verified);
        req.user = verified;
        next();
    } catch (error) {
        console.error('Token verification error:', error.message);
        res.status(401).json({ success: false, message: `Invalid token: ${error.message}` });
    }
};

module.exports = verifyToken;
