import express from 'express';
import { connectToDatabase } from '../lib/db.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const router = express.Router();


router.post('/register', async (req, res) => {
  const { username, email, password, dob, gender, phone, city } = req.body;
  try {
    const db = await connectToDatabase();
    const [rows] = await db.query('SELECT * FROM users WHERE email=?', [email]);
    if (rows.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }
    const hashPassword = await bcrypt.hash(password, 10);
    await db.query('INSERT INTO users(username,email,password,dob,gender,phone,city) VALUES(?,?,?,?,?,?,?)', [
      username,
      email,
      hashPassword,
      dob,
      gender,
      phone,
      city,
    ]);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json(err);
  }
});



router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const db = await connectToDatabase();
    const [rows] = await db.query('SELECT * FROM users WHERE email=?', [email]);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    const isMatch = await bcrypt.compare(password, rows[0].password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: rows[0].id }, process.env.JWT_KEY, { expiresIn: '1h' });

    
    const isAdmin = rows[0].admin; 

   
    if (isAdmin) {
      return res.status(201).json({ token: token, redirect: '/admin' });
    } else {
      return res.status(201).json({ token: token, redirect: '/home' });
    }
  } catch (err) {
    res.status(500).json(err);
  }
});



const verifyToken = async (req, res, next) => {
  const token = req.headers['authorization'].split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Access denied' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_KEY);
    req.userId = decoded.id;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};


router.get('/home', verifyToken, async (req, res) => {
  try {
    const db = await connectToDatabase();
    const [rows] = await db.query('SELECT * FROM users WHERE id=?', [req.userId]);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    return res.status(200).json({ user: rows[0] });
  } catch (err) {
    return res.status(500).json({ message: 'Internal server error' });
  }
});


router.get('/admin', async (req, res) => {
  const db = await connectToDatabase();
  const [rows] = await db.query('SELECT * FROM users');
  res.status(200).json({ users: rows });
});


router.post('/admin/reject', async (req, res) => {
  const { userId } = req.body; 

  try {
    const db = await connectToDatabase();
    
    
    const [userRows] = await db.query('SELECT * FROM users WHERE id=?', [userId]);
    if (userRows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    
    await db.query('UPDATE users SET status="Rejected" WHERE id=?', [userId]);

    
    await db.query('DELETE FROM users WHERE id=?', [userId]);

    res.status(200).json({ message: 'User rejected and deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error while rejecting the user', error: err.message });
  }
});
router.post('/admin/verify', async (req, res) => {
    const { userId } = req.body;
    try {
      const db = await connectToDatabase();
  
      
      const [userRows] = await db.query('SELECT status FROM users WHERE id = ?', [userId]);
      
      if (userRows.length === 0) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      const currentStatus = userRows[0].status;
  
      if (currentStatus === 'Verified') {
        return res.status(400).json({ message: 'User is already verified' });
      }
  
      
      await db.query('UPDATE users SET status = ?, isVerified = ? WHERE id = ?', ['Verified', true, userId]);
  
      res.status(200).json({ message: 'User verified successfully' });
    } catch (err) {
      res.status(500).json({ message: 'Error verifying user', error: err });
    }
  });

  
router.put('/home', verifyToken, async (req, res) => {
  const { username, email, dob, gender, phone, city } = req.body;

  try {
    const db = await connectToDatabase();
    const [result] = await db.query(
      'UPDATE users SET username=?, email=?, dob=?, gender=?, phone=?, city=? WHERE id=?',
      [username, email, dob, gender, phone, city, req.userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ message: 'User details updated successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
});

router.put('/change-password', verifyToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  try {
    const db = await connectToDatabase();

    
    const [rows] = await db.query('SELECT * FROM users WHERE id=?', [req.userId]);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = rows[0];

    
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }

    
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    
    await db.query('UPDATE users SET password=? WHERE id=?', [hashedPassword, req.userId]);

    res.status(200).json({ message: 'Password changed successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
});


export default router;