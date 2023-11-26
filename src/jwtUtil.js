import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
dotenv.config();

export function generateToken(user) {
  const payload = {
    userId: user.id,
    email: user.email,
    name: user.name,
    time: new Date(),
    randomString: Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15),
    // You can add more user details here if needed
  };

  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
}

export function verifyToken(token) {
  return jwt.verify(token, process.env.JWT_SECRET);
}