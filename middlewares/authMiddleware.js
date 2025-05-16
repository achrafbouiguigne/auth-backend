const jwt = require('jsonwebtoken');
const pool = require('../config/db');

const protect = async (req, res, next) => {
  let token;
  
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
    
      token = req.headers.authorization.split(' ')[1];
      
      
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      
      const user = await pool.query(
        'SELECT id, username, email FROM users WHERE id = $1',
        [decoded.id]
      );
      
      if (user.rows.length === 0) {
        return res.status(401).json({ message: 'Not authorized' });
      }
      
      req.user = user.rows[0];
      next();
    } catch (error) {
      console.error(error);
      res.status(401).json({ message: 'Not authorized' });
    }
  }
  
  if (!token) {
    res.status(401).json({ message: 'Not authorized, no token' });
  }
};

module.exports = { protect };