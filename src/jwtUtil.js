import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
dotenv.config();

export function generateToken(user) {
  const payload = {
    userId: user.id,
    email: user.email
    // You can add more user details here if needed
  };

  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
}
