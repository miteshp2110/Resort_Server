import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mysql from 'mysql2/promise';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import ExcelJS from 'exceljs';
import fs from 'fs-extra';
import xlsx from 'xlsx';
import PDFDocument from 'pdfkit';
// import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const excelReportsDir = path.join(__dirname, 'excelReports');
fs.ensureDirSync(excelReportsDir);

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, '../uploads/'));
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage: storage });

// Database connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

function formatMySQLDate(dateStr) {
  const date = new Date(dateStr)
  return date.toISOString().slice(0, 19).replace('T', ' ')
}

// Email transport configuration
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: process.env.EMAIL_PORT === '465', // true for 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    
    // Check if user still exists in database
    const [users] = await pool.query('SELECT id, username, role FROM users WHERE id = ?', [verified.id]);
    
    if (users.length === 0) {
      return res.status(401).json({ message: 'User no longer exists' });
    }
    
    req.user.role = users[0].role;
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Invalid token' });
  }
};

// Admin middleware
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied. Admin role required.' });
  }
  next();
};

// Kitchen staff middleware
const isKitchenStaff = (req, res, next) => {
  if (req.user.role !== 'admin' && req.user.role !== 'kitchen') {
    return res.status(403).json({ message: 'Access denied. Kitchen role required.' });
  }
  next();
};

// Reception staff middleware
const isReception = (req, res, next) => {
  if (req.user.role !== 'admin' && req.user.role !== 'reception') {
    return res.status(403).json({ message: 'Access denied. Reception role required.' });
  }
  next();
};

// Auth Routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Validate input
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }
    
    // Check if user exists
    const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    
    if (users.length === 0) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
    
    const user = users[0];
    
    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
    
    // Create token
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );
    
    res.status(200).json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// User Management Routes
app.get('/api/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, username, full_name, email, role, created_at FROM users');
    res.status(200).json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { username, password, full_name, email, role } = req.body;
    
    // Validate input
    if (!username || !password || !full_name || !role) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    
    // Check if username already exists
    const [existingUsers] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ message: 'Username already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Insert new user
    const [result] = await pool.query(
      'INSERT INTO users (username, password, full_name, email, role) VALUES (?, ?, ?, ?, ?)',
      [username, hashedPassword, full_name, email, role]
    );
    
    res.status(201).json({
      message: 'User created successfully',
      user: {
        id: result.insertId,
        username,
        full_name,
        email,
        role
      }
    });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const { full_name, email, role } = req.body;
    
    // Update user without changing password
    await pool.query(
      'UPDATE users SET full_name = ?, email = ?, role = ? WHERE id = ?',
      [full_name, email, role, userId]
    );
    
    res.status(200).json({ message: 'User updated successfully' });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/users/:id/password', authenticateToken, isAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ message: 'Password is required' });
    }
    
    // Hash and update password
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId]);
    
    res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Error updating password:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    
    // Prevent deleting self
    if (parseInt(userId) === req.user.id) {
      return res.status(400).json({ message: 'Cannot delete your own account' });
    }
    
    await pool.query('DELETE FROM users WHERE id = ?', [userId]);
    res.status(200).json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Settings Routes
app.get('/api/settings', async (req, res) => {
  try {
    const [settings] = await pool.query('SELECT * FROM settings LIMIT 1');
    
    if (settings.length === 0) {
      return res.status(404).json({ message: 'Settings not found' });
    }
    
    res.status(200).json(settings[0]);
  } catch (error) {
    console.error('Error fetching settings:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/settings', authenticateToken, isAdmin, upload.single('logo'), async (req, res) => {
  try {
    const { resort_name, resort_gstin, kitchen_gstin, resort_address, resort_contact, resort_email, tax_rate } = req.body;
    
    let logo_path = null;
    if (req.file) {
      logo_path = req.file.path.replace(/\\/g, '/').replace('uploads/', '');
    }
    
    // Update settings
    const updateQuery = logo_path
      ? 'UPDATE settings SET resort_name = ?, resort_gstin = ?, kitchen_gstin = ?, resort_address = ?, resort_contact = ?, resort_email = ?, tax_rate = ?, logo_path = ? WHERE id = 1'
      : 'UPDATE settings SET resort_name = ?, resort_gstin = ?, kitchen_gstin = ?, resort_address = ?, resort_contact = ?, resort_email = ?, tax_rate = ? WHERE id = 1';
    
    const updateParams = logo_path
      ? [resort_name, resort_gstin, kitchen_gstin, resort_address, resort_contact, resort_email, tax_rate, logo_path]
      : [resort_name, resort_gstin, kitchen_gstin, resort_address, resort_contact, resort_email, tax_rate];
    
    await pool.query(updateQuery, updateParams);
    
    res.status(200).json({ message: 'Settings updated successfully' });
  } catch (error) {
    console.error('Error updating settings:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Menu Items Routes
app.get('/api/menu-items', async (req, res) => {
  try {
    const type = req.query.type;
    let query = 'SELECT * FROM menu_items';
    
    if (type) {
      query += ' WHERE type = ?';
      const [items] = await pool.query(query, [type]);
      return res.status(200).json(items);
    }
    
    const [items] = await pool.query(query);
    res.status(200).json(items);
  } catch (error) {
    console.error('Error fetching menu items:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/menu-items', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { name, description, price, gst_percentage, type } = req.body;
    
    if (!name || !price || !type || !gst_percentage) {
      return res.status(400).json({ message: 'Name, price, GST percentage, and type are required' });
    }
    
    const [result] = await pool.query(
      'INSERT INTO menu_items (name, description, price, gst_percentage, type) VALUES (?, ?, ?, ?, ?)',
      [name, description || null, price, gst_percentage, type]
    );
    
    res.status(201).json({
      message: 'Menu item created successfully',
      item: {
        id: result.insertId,
        name,
        description,
        price,
        gst_percentage,
        type
      }
    });
  } catch (error) {
    console.error('Error creating menu item:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/menu-items/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const itemId = req.params.id;
    const { name, description, price, gst_percentage, type, is_active } = req.body;
    
    await pool.query(
      'UPDATE menu_items SET name = ?, description = ?, price = ?, gst_percentage = ?, type = ?, is_active = ? WHERE id = ?',
      [name, description || null, price, gst_percentage, type, is_active, itemId]
    );
    
    res.status(200).json({ message: 'Menu item updated successfully' });
  } catch (error) {
    console.error('Error updating menu item:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/menu-items/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const itemId = req.params.id;
    
    // Check if item is being used
    const [invoiceItems] = await pool.query('SELECT * FROM invoice_items WHERE item_id = ? LIMIT 1', [itemId]);
    if (invoiceItems.length > 0) {
      return res.status(400).json({ message: 'Cannot delete item as it is used in invoices' });
    }
    
    await pool.query('DELETE FROM menu_items WHERE id = ?', [itemId]);
    res.status(200).json({ message: 'Menu item deleted successfully' });
  } catch (error) {
    console.error('Error deleting menu item:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Services Routes
app.get('/api/services', async (req, res) => {
  try {
    const [services] = await pool.query('SELECT * FROM services');
    res.status(200).json(services);
  } catch (error) {
    console.error('Error fetching services:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/services', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { name, description, price, gst_percentage } = req.body;
    
    if (!name || !price || !gst_percentage) {
      return res.status(400).json({ message: 'Name, price, and GST percentage are required' });
    }
    
    const [result] = await pool.query(
      'INSERT INTO services (name, description, price, gst_percentage) VALUES (?, ?, ?, ?)',
      [name, description || null, price, gst_percentage]
    );
    
    res.status(201).json({
      message: 'Service created successfully',
      service: {
        id: result.insertId,
        name,
        description,
        price,
        gst_percentage
      }
    });
  } catch (error) {
    console.error('Error creating service:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/services/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const serviceId = req.params.id;
    const { name, description, price, gst_percentage, is_active } = req.body;
    
    await pool.query(
      'UPDATE services SET name = ?, description = ?, price = ?, gst_percentage = ?, is_active = ? WHERE id = ?',
      [name, description || null, price, gst_percentage, is_active, serviceId]
    );
    
    res.status(200).json({ message: 'Service updated successfully' });
  } catch (error) {
    console.error('Error updating service:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/services/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const serviceId = req.params.id;
    
    // Check if service is being used
    const [invoiceItems] = await pool.query('SELECT * FROM invoice_items WHERE service_id = ? LIMIT 1', [serviceId]);
    if (invoiceItems.length > 0) {
      return res.status(400).json({ message: 'Cannot delete service as it is used in invoices' });
    }
    
    await pool.query('DELETE FROM services WHERE id = ?', [serviceId]);
    res.status(200).json({ message: 'Service deleted successfully' });
  } catch (error) {
    console.error('Error deleting service:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Guests Routes
app.get('/api/guests', authenticateToken, async (req, res) => {
  try {
    const { search } = req.query;
    
    let query = 'SELECT * FROM guests';
    let params = [];
    
    if (search) {
      query += ' WHERE name LIKE ? OR mobile LIKE ? OR room_number LIKE ?';
      params = [`%${search}%`, `%${search}%`, `%${search}%`];
    }
    
    query += ' ORDER BY created_at DESC';
    
    const [guests] = await pool.query(query, params);
    res.status(200).json(guests);
  } catch (error) {
    console.error('Error fetching guests:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/guests', authenticateToken, async (req, res) => {
  try {
    const { name, mobile, email, room_number, check_in_date, check_out_date } = req.body;
    
    if (!name) {
      return res.status(400).json({ message: 'Guest name is required' });
    }
    
    const [result] = await pool.query(
      'INSERT INTO guests (name, mobile, email, room_number, check_in_date, check_out_date) VALUES (?, ?, ?, ?, ?, ?)',
      [name, mobile, email, room_number, formatMySQLDate(check_in_date), formatMySQLDate(check_out_date)]
    );
    
    res.status(201).json({
      message: 'Guest created successfully',
      guest: {
        id: result.insertId,
        name,
        mobile,
        email,
        room_number,
        check_in_date,
        check_out_date
      }
    });
  } catch (error) {
    console.error('Error creating guest:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Kitchen Orders Routes
app.get('/api/kitchen-orders', authenticateToken, async (req, res) => {
  try {
    const { start_date, end_date, status } = req.query;
    
    let query = 'SELECT ko.*, u.username as created_by_name FROM kitchen_orders ko LEFT JOIN users u ON ko.created_by = u.id';
    let conditions = [];
    let params = [];
    
    if (start_date) {
      conditions.push('ko.order_date >= ?');
      params.push(start_date);
    }
    
    if (end_date) {
      conditions.push('ko.order_date <= ?');
      params.push(end_date + ' 23:59:59');
    }
    
    if (status) {
      conditions.push('ko.status = ?');
      params.push(status);
    }
    
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += ' ORDER BY ko.order_date DESC';
    
    const [orders] = await pool.query(query, params);
    res.status(200).json(orders);
  } catch (error) {
    console.error('Error fetching kitchen orders:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/kitchen-orders/:id', authenticateToken, async (req, res) => {
  try {
    const orderId = req.params.id;
    
    // Get order
    const [orders] = await pool.query(
      'SELECT ko.*, u.username as created_by_name FROM kitchen_orders ko LEFT JOIN users u ON ko.created_by = u.id WHERE ko.id = ?',
      [orderId]
    );
    
    if (orders.length === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }
    
    // Get order items
    const [items] = await pool.query(
      `SELECT koi.*, mi.name 
       FROM kitchen_order_items koi 
       JOIN menu_items mi ON koi.item_id = mi.id 
       WHERE koi.order_id = ?`,
      [orderId]
    );
    
    const order = orders[0];
    order.items = items;
    
    res.status(200).json(order);
  } catch (error) {
    console.error('Error fetching kitchen order:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/kitchen-orders', authenticateToken, isKitchenStaff, async (req, res) => {
  try {
    const { guest_id, room_number, guest_name, order_type, items } = req.body;
    
    if (!guest_name || !order_type || !items || items.length === 0) {
      return res.status(400).json({ message: 'Guest name, order type, and items are required' });
    }
    
    // Start transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      // Generate order number
      const orderDate = new Date();
      const orderNumber = 'KO' + orderDate.getFullYear() +
        (orderDate.getMonth() + 1).toString().padStart(2, '0') +
        orderDate.getDate().toString().padStart(2, '0') +
        Math.floor(Math.random() * 10000).toString().padStart(4, '0');
      
      // Calculate totals
      let subtotal = 0;
      let taxAmount = 0;
      
      for (const item of items) {
        const quantity = parseInt(item.quantity);
        const rate = parseFloat(item.rate);
        const gstPercentage = parseFloat(item.gst_percentage);
        
        const itemTotal = quantity * rate;
        const itemGst = itemTotal * (gstPercentage / 100);
        
        subtotal += itemTotal;
        taxAmount += itemGst;
      }
      
      const totalAmount = subtotal + taxAmount;
      
      // Create order
      const [orderResult] = await connection.query(
        `INSERT INTO kitchen_orders 
         (order_number, guest_id, room_number, guest_name, order_type, subtotal, tax_amount, total_amount, created_by) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [orderNumber, guest_id || null, room_number || null, guest_name, order_type, subtotal, taxAmount, totalAmount, req.user.id]
      );
      
      const orderId = orderResult.insertId;
      
      // Insert order items
      for (const item of items) {
        const quantity = parseInt(item.quantity);
        const rate = parseFloat(item.rate);
        const gstPercentage = parseFloat(item.gst_percentage);
        
        const itemTotal = quantity * rate;
        const itemGst = itemTotal * (gstPercentage / 100);
        const itemTotalWithGst = itemTotal + itemGst;
        
        await connection.query(
          `INSERT INTO kitchen_order_items 
           (order_id, item_id, quantity, rate, gst_percentage, gst_amount, total) 
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [orderId, item.id, quantity, rate, gstPercentage, itemGst, itemTotalWithGst]
        );
      }
      
      await connection.commit();
      
      res.status(201).json({
        message: 'Kitchen order created successfully',
        order: {
          id: orderId,
          order_number: orderNumber,
          subtotal,
          tax_amount: taxAmount,
          total_amount: totalAmount
        }
      });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error creating kitchen order:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/kitchen-orders/:id/status', authenticateToken, isKitchenStaff, async (req, res) => {
  try {
    const orderId = req.params.id;
    const { status } = req.body;
    
    if (!status) {
      return res.status(400).json({ message: 'Status is required' });
    }
    
    await pool.query('UPDATE kitchen_orders SET status = ? WHERE id = ?', [status, orderId]);
    
    res.status(200).json({ message: 'Order status updated successfully' });
  } catch (error) {
    console.error('Error updating order status:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Invoice Routes
app.get('/api/invoices', authenticateToken, async (req, res) => {
  try {
    const { start_date, end_date, type } = req.query;
    
    let query = 'SELECT i.*, u.username as created_by_name FROM invoices i LEFT JOIN users u ON i.created_by = u.id';
    let conditions = [];
    let params = [];
    
    if (start_date) {
      conditions.push('i.invoice_date >= ?');
      params.push(start_date);
    }
    
    if (end_date) {
      conditions.push('i.invoice_date <= ?');
      params.push(end_date + ' 23:59:59');
    }
    
    if (type) {
      conditions.push('i.type = ?');
      params.push(type);
    }
    
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += ' ORDER BY i.invoice_date DESC';
    
    const [invoices] = await pool.query(query, params);
    res.status(200).json(invoices);
  } catch (error) {
    console.error('Error fetching invoices:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/invoices/:id', authenticateToken, async (req, res) => {
  try {
    const invoiceId = req.params.id;
    
    // Get invoice
    const [invoices] = await pool.query(
      'SELECT i.*, u.username as created_by_name FROM invoices i LEFT JOIN users u ON i.created_by = u.id WHERE i.id = ?',
      [invoiceId]
    );
    
    if (invoices.length === 0) {
      return res.status(404).json({ message: 'Invoice not found' });
    }
    
    // Get invoice items
    const [items] = await pool.query(
      `SELECT ii.* FROM invoice_items ii WHERE ii.invoice_id = ?`,
      [invoiceId]
    );
    
    const invoice = invoices[0];
    invoice.items = items;
    
    res.status(200).json(invoice);
  } catch (error) {
    console.error('Error fetching invoice:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/invoices', authenticateToken, isReception, async (req, res) => {
  try {
    const { guest_id, room_number, guest_name, guest_mobile, type, items, payment_status, payment_method, notes,bookingDate } = req.body;
    
    if (!guest_name || !type || !items || items.length === 0) {
      return res.status(400).json({ message: 'Guest name, invoice type, and items are required' });
    }
    
    // Start transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      // Generate invoice number
      const invoiceDate = new Date();
      const invoiceNumber = (type === 'resort' ? 'RS' : 'KT') + invoiceDate.getFullYear() +
        (invoiceDate.getMonth() + 1).toString().padStart(2, '0') +
        invoiceDate.getDate().toString().padStart(2, '0') +
        Math.floor(Math.random() * 10000).toString().padStart(4, '0');
      
      // Calculate totals
      let subtotal = 0;
      let taxAmount = 0;
      
      for (const item of items) {
        const quantity = parseInt(item.quantity);
        const rate = parseFloat(item.rate);
        const gstPercentage = parseFloat(item.gst_percentage);
        
        const itemTotal = quantity * rate;
        const itemGst = itemTotal * (gstPercentage / 100);
        
        subtotal += itemTotal;
        taxAmount += itemGst;
      }
      
      const totalAmount = subtotal + taxAmount;
      
      // Create invoice
      const [invoiceResult] = await connection.query(
        `INSERT INTO invoices 
         (invoice_number, invoice_date, guest_id, room_number, guest_name, guest_mobile, 
          type, subtotal, tax_amount, total_amount, payment_status, payment_method, notes, created_by, booking_date) 
         VALUES (?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)`,
        [invoiceNumber, guest_id || null, room_number || null, guest_name, guest_mobile || null, 
         type, subtotal, taxAmount, totalAmount, payment_status || 'pending', payment_method || 'cash', notes || null, req.user.id, bookingDate || null]
      );
      
      const invoiceId = invoiceResult.insertId;
      
      // Insert invoice items
      for (const item of items) {
        const quantity = parseInt(item.quantity);
        const rate = parseFloat(item.rate);
        const gstPercentage = parseFloat(item.gst_percentage);
        
        const itemTotal = quantity * rate;
        const itemGst = itemTotal * (gstPercentage / 100);
        const itemTotalWithGst = itemTotal + itemGst;
        
        await connection.query(
          `INSERT INTO invoice_items 
           (invoice_id, item_id, service_id, item_name, quantity, rate, gst_percentage, gst_amount, total) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [invoiceId, item.item_id || null, item.service_id || null, item.name, quantity, rate, gstPercentage, itemGst, itemTotalWithGst]
        );
      }
      
      await connection.commit();
      
      res.status(201).json({
        message: 'Invoice created successfully',
        invoice: {
          id: invoiceId,
          invoice_number: invoiceNumber,
          subtotal,
          tax_amount: taxAmount,
          total_amount: totalAmount
        }
      });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error creating invoice:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/invoices/:id/payment', authenticateToken, isReception, async (req, res) => {
  try {
    const invoiceId = req.params.id;
    const { payment_status, payment_method } = req.body;
    
    if (!payment_status) {
      return res.status(400).json({ message: 'Payment status is required' });
    }
    
    await pool.query(
      'UPDATE invoices SET payment_status = ?, payment_method = ? WHERE id = ?',
      [payment_status, payment_method || 'cash', invoiceId]
    );
    
    res.status(200).json({ message: 'Payment status updated successfully' });
  } catch (error) {
    console.error('Error updating payment status:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create invoice from kitchen order
app.post('/api/kitchen-orders/:id/create-invoice', authenticateToken, isReception, async (req, res) => {
  try {
    const orderId = req.params.id;
    const { payment_status, payment_method } = req.body;
    
    // Start transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      // Get order details
      const [orders] = await connection.query(
        'SELECT * FROM kitchen_orders WHERE id = ?',
        [orderId]
      );
      
      if (orders.length === 0) {
        await connection.rollback();
        return res.status(404).json({ message: 'Order not found' });
      }
      
      const order = orders[0];
      
      // Check if invoice already exists
      if (order.invoice_id) {
        await connection.rollback();
        return res.status(400).json({ message: 'Invoice already exists for this order' });
      }
      
      // Get order items
      const [orderItems] = await connection.query(
        `SELECT koi.*, mi.name 
         FROM kitchen_order_items koi 
         JOIN menu_items mi ON koi.item_id = mi.id 
         WHERE koi.order_id = ?`,
        [orderId]
      );
      
      // Generate invoice number
      const invoiceDate = new Date();
      const invoiceNumber = 'KT' + invoiceDate.getFullYear() +
        (invoiceDate.getMonth() + 1).toString().padStart(2, '0') +
        invoiceDate.getDate().toString().padStart(2, '0') +
        Math.floor(Math.random() * 10000).toString().padStart(4, '0');
      
      // Create invoice
      const [invoiceResult] = await connection.query(
        `INSERT INTO invoices 
         (invoice_number, invoice_date, guest_id, room_number, guest_name, guest_mobile, 
          type, subtotal, tax_amount, total_amount, payment_status, payment_method, created_by) 
         VALUES (?, NOW(), ?, ?, ?, NULL, 'kitchen', ?, ?, ?, ?, ?, ?)`,
        [invoiceNumber, order.guest_id, order.room_number, order.guest_name, 
         order.subtotal, order.tax_amount, order.total_amount, payment_status || 'pending', payment_method || 'cash', req.user.id]
      );
      
      const invoiceId = invoiceResult.insertId;
      
      // Insert invoice items
      for (const item of orderItems) {
        await connection.query(
          `INSERT INTO invoice_items 
           (invoice_id, item_id, service_id, item_name, quantity, rate, gst_percentage, gst_amount, total) 
           VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?)`,
          [invoiceId, item.item_id, item.name, item.quantity, item.rate, item.gst_percentage, item.gst_amount, item.total]
        );
      }
      
      // Update order with invoice reference
      await connection.query(
        'UPDATE kitchen_orders SET invoice_id = ? WHERE id = ?',
        [invoiceId, orderId]
      );
      
      await connection.commit();
      
      res.status(201).json({
        message: 'Invoice created successfully from order',
        invoice: {
          id: invoiceId,
          invoice_number: invoiceNumber,
          subtotal: order.subtotal,
          tax_amount: order.tax_amount,
          total_amount: order.total_amount
        }
      });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error creating invoice from order:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Email invoice
app.post('/api/invoices/:id/email', authenticateToken, async (req, res) => {
  try {
    const invoiceId = req.params.id;
    const [emailResult] = await pool.query("select email from guests where id = (select guest_id from invoices where id = ?)",[invoiceId]);

    const email = emailResult[0].email
    
    if (!email) {
      return res.status(400).json({ message: 'Email address is required' });
    }
    
    // Get invoice details
    const [invoices] = await pool.query(
      'SELECT i.*, s.resort_name, s.resort_address, s.resort_contact, s.resort_email, s.resort_gstin, s.kitchen_gstin FROM invoices i JOIN settings s ON 1=1 WHERE i.id = ?',
      [invoiceId]
    );
    
    if (invoices.length === 0) {
      return res.status(404).json({ message: 'Invoice not found' });
    }
    
    const invoice = invoices[0];
    
    // Get invoice items
    const [items] = await pool.query(
      'SELECT * FROM invoice_items WHERE invoice_id = ?',
      [invoiceId]
    );
    
    // Create email content
    const htmlContent = `
      <h2>${invoice.resort_name}</h2>
      <p>${invoice.resort_address}</p>
      <p>Contact: ${invoice.resort_contact}</p>
      <p>GSTIN: ${invoice.type === 'resort' ? invoice.resort_gstin : invoice.kitchen_gstin}</p>
      
      <h3>Invoice #${invoice.invoice_number}</h3>
      <p>Date: ${new Date(invoice.invoice_date).toDateString()}</p>
      <p>Guest: ${invoice.guest_name}</p>
      ${invoice.room_number ? `<p>Room: ${invoice.room_number}</p>` : ''}
      
      <table style="width: 100%; border-collapse: collapse;">
        <thead>
          <tr style="background-color: #f2f2f2;">
            <th style="padding: 8px; border: 1px solid #ddd;">Item</th>
            <th style="padding: 8px; border: 1px solid #ddd;">Qty</th>
            <th style="padding: 8px; border: 1px solid #ddd;">Rate</th>
            <th style="padding: 8px; border: 1px solid #ddd;">Amount</th>
            <th style="padding: 8px; border: 1px solid #ddd;">GST%</th>
            <th style="padding: 8px; border: 1px solid #ddd;">GST Amount</th>
            <th style="padding: 8px; border: 1px solid #ddd;">Total</th>
          </tr>
        </thead>
        <tbody>
          ${items.map(item => `
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;">${item.item_name}</td>
              <td style="padding: 8px; border: 1px solid #ddd;">${item.quantity}</td>
              <td style="padding: 8px; border: 1px solid #ddd;">${(item.rate)}</td>
              <td style="padding: 8px; border: 1px solid #ddd;">${(item.quantity * item.rate).toFixed(2)}</td>
              <td style="padding: 8px; border: 1px solid #ddd;">${item.gst_percentage}%</td>
              <td style="padding: 8px; border: 1px solid #ddd;">${item.gst_amount}</td>
              <td style="padding: 8px; border: 1px solid #ddd;">${item.total}</td>
            </tr>
          `).join('')}
        </tbody>
        <tfoot>
          <tr style="font-weight: bold;">
            <td colspan="3" style="padding: 8px; border: 1px solid #ddd; text-align: right;">Subtotal:</td>
            <td colspan="4" style="padding: 8px; border: 1px solid #ddd;">${invoice.subtotal}</td>
          </tr>
          <tr style="font-weight: bold;">
            <td colspan="3" style="padding: 8px; border: 1px solid #ddd; text-align: right;">GST:</td>
            <td colspan="4" style="padding: 8px; border: 1px solid #ddd;">${invoice.tax_amount}</td>
          </tr>
          <tr style="font-weight: bold;">
            <td colspan="3" style="padding: 8px; border: 1px solid #ddd; text-align: right;">Total:</td>
            <td colspan="4" style="padding: 8px; border: 1px solid #ddd;">${invoice.total_amount}</td>
          </tr>
        </tfoot>
      </table>
      
      <p>Payment Status: ${invoice.payment_status}</p>
      
      <p style="margin-top: 20px;">Thank you for your business!</p>
    `;
    
    // Send email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: `Invoice #${invoice.invoice_number} from ${invoice.resort_name}`,
      html: htmlContent,
    };
    
    await transporter.sendMail(mailOptions);
    
    res.status(200).json({ message: 'Invoice sent successfully to ' + email });
  } catch (error) {
    console.error('Error sending invoice by email:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Reports Routes
app.get('/api/reports/sales', authenticateToken, async (req, res) => {
  try {
    const { start_date, end_date, type } = req.query;
    
    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Start date and end date are required' });
    }
    
    let query = `
      SELECT 
        DATE(invoice_date) as date,
        type,
        COUNT(*) as invoice_count,
        SUM(subtotal) as subtotal,
        SUM(tax_amount) as tax_amount,
        SUM(total_amount) as total_amount
      FROM invoices
      WHERE invoice_date >= ? AND invoice_date <= ?
    `;
    
    let params = [start_date, end_date + ' 23:59:59'];
    
    if (type) {
      query += ' AND type = ?';
      params.push(type);
    }
    
    query += ' GROUP BY DATE(invoice_date), type ORDER BY date';
    
    const [results] = await pool.query(query, params);
    
    // Format the response
    const data = {
      summary: {
        invoice_count: 0,
        subtotal: 0,
        tax_amount: 0,
        total_amount: 0
      },
      daily: []
    };
    
    results.forEach(row => {
      data.summary.invoice_count += Number(row.invoice_count || 0);
      data.summary.subtotal += Number(row.subtotal || 0);
      data.summary.tax_amount += Number(row.tax_amount || 0);
      data.summary.total_amount += Number(row.total_amount || 0);
      
      data.daily.push({
        date: row.date,
        type: row.type,
        invoice_count: Number(row.invoice_count || 0),
        subtotal: Number(row.subtotal || 0),
        tax_amount: Number(row.tax_amount || 0),
        total_amount: Number(row.total_amount || 0)
      });
    });
    
    res.status(200).json(data);
  } catch (error) {
    console.error('Error generating sales report:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/reports/gst', authenticateToken, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Start date and end date are required' });
    }
    
    const query = `
      SELECT 
        type,
        SUM(subtotal) as taxable_amount,
        SUM(tax_amount) as tax_amount,
        SUM(total_amount) as total_amount
      FROM invoices
      WHERE invoice_date >= ? AND invoice_date <= ?
      GROUP BY type
    `;
    
    const [results] = await pool.query(query, [start_date, end_date + ' 23:59:59']);
    
    // Get GSTIN information
    const [settings] = await pool.query('SELECT resort_gstin, kitchen_gstin FROM settings LIMIT 1');
    
    // Format the response
    const data = {
      period: {
        start_date,
        end_date
      },
      resort: {
        gstin: settings[0].resort_gstin,
        taxable_amount: 0,
        tax_amount: 0,
        total_amount: 0
      },
      kitchen: {
        gstin: settings[0].kitchen_gstin,
        taxable_amount: 0,
        tax_amount: 0,
        total_amount: 0
      }
    };
    
    results.forEach(row => {
      if (row.type === 'resort') {
        data.resort.taxable_amount = Number(row.taxable_amount || 0);
        data.resort.tax_amount = Number(row.tax_amount || 0);
        data.resort.total_amount = Number(row.total_amount || 0);
      } else if (row.type === 'kitchen') {
        data.kitchen.taxable_amount = Number(row.taxable_amount || 0);
        data.kitchen.tax_amount = Number(row.tax_amount || 0);
        data.kitchen.total_amount = Number(row.total_amount || 0);
      }
    });
    
    res.status(200).json(data);
  } catch (error) {
    console.error('Error generating GST report:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/reports/kitchen-items', authenticateToken, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Start date and end date are required' });
    }
    
    const query = `
      SELECT 
        mi.id,
        mi.name,
        SUM(koi.quantity) as total_quantity,
        SUM(koi.total) as total_amount
      FROM kitchen_order_items koi
      JOIN menu_items mi ON koi.item_id = mi.id
      JOIN kitchen_orders ko ON koi.order_id = ko.id
      WHERE ko.order_date >= ? AND ko.order_date <= ?
      GROUP BY mi.id, mi.name
      ORDER BY total_quantity DESC
    `;
    
    const [results] = await pool.query(query, [start_date, end_date + ' 23:59:59']);
    
    // Apply Number() conversion to each result item
    const formattedResults = results.map(item => ({
      id: item.id,
      name: item.name,
      total_quantity: Number(item.total_quantity || 0),
      total_amount: Number(item.total_amount || 0)
    }));
    
    res.status(200).json(formattedResults);
  } catch (error) {
    console.error('Error generating kitchen items report:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/reports/dashboard', authenticateToken, async (req, res) => {
  try {
    // Get today's date
    const today = new Date().toISOString().split('T')[0];
    
    // Get current month dates
    const now = new Date();
    const currentMonth = now.getMonth();
    const currentYear = now.getFullYear();
    const firstDay = new Date(currentYear, currentMonth, 1).toISOString().split('T')[0];
    const lastDay = new Date(currentYear, currentMonth + 1, 0).toISOString().split('T')[0];
    
    // Today's statistics
    const [todayStats] = await pool.query(`
      SELECT 
        type,
        COUNT(*) as count,
        SUM(total_amount) as total
      FROM invoices
      WHERE DATE(invoice_date) = ?
      GROUP BY type
    `, [today]);
    
    // Current month statistics
    const [monthStats] = await pool.query(`
      SELECT 
        type,
        COUNT(*) as count,
        SUM(total_amount) as total
      FROM invoices
      WHERE invoice_date >= ? AND invoice_date <= ?
      GROUP BY type
    `, [firstDay, lastDay + ' 23:59:59']);
    
    // Recent invoices
    const [recentInvoices] = await pool.query(`
      SELECT 
        id, invoice_number, invoice_date, guest_name, type, total_amount, payment_status
      FROM invoices
      ORDER BY invoice_date DESC
      LIMIT 5
    `);
    
    // Pending kitchen orders
    const [pendingOrders] = await pool.query(`
      SELECT 
        id, order_number, order_date, guest_name, room_number, total_amount, status
      FROM kitchen_orders
      WHERE status IN ('pending', 'processing')
      ORDER BY order_date ASC
    `);
    
    // Format the response
    const data = {
      today: {
        date: today,
        resort: {
          count: 0,
          total: 0
        },
        kitchen: {
          count: 0,
          total: 0
        },
        total: 0
      },
      month: {
        start_date: firstDay,
        end_date: lastDay,
        resort: {
          count: 0,
          total: 0
        },
        kitchen: {
          count: 0,
          total: 0
        },
        total: 0
      },
      recent_invoices: recentInvoices,
      pending_orders: pendingOrders
    };
    
    // Process today's stats
    todayStats.forEach(row => {
      if (row.type === 'resort') {
        data.today.resort = {
          count: row.count,
          total: row.total
        };
      } else if (row.type === 'kitchen') {
        data.today.kitchen = {
          count: row.count,
          total: row.total
        };
      }
      data.today.total += row.total;
    });
    
    // Process month's stats
    monthStats.forEach(row => {
      if (row.type === 'resort') {
        data.month.resort = {
          count: row.count,
          total: row.total
        };
      } else if (row.type === 'kitchen') {
        data.month.kitchen = {
          count: row.count,
          total: row.total
        };
      }
      data.month.total += row.total;
    });
    
    res.status(200).json(data);
  } catch (error) {
    console.error('Error fetching dashboard data:', error);
    res.status(500).json({ message: 'Server error' });
  }
});




app.get('/api/invoices/aggregated/resort', async (req, res) => {
  try {
    const { from_date, to_date, guest_name } = req.query;
    
    if (!from_date || !to_date) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'Both from_date and to_date are required' 
      });
    }

    // Format dates for query
    const formattedFromDate = new Date(from_date).toISOString().split('T')[0];
    const formattedToDate = new Date(to_date).toISOString().split('T')[0] + ' 23:59:59';

    // Base query parts
    let guestWhereCondition = '';
    
    if (guest_name) {
      guestWhereCondition = 'AND i.guest_name LIKE ?';
    }

    // Get resort invoices
    const invoiceQuery = `
      SELECT 
        i.id, 
        i.invoice_number, 
        i.invoice_date, 
        i.guest_id,
        i.room_number,
        i.guest_name, 
        i.guest_mobile,
        i.subtotal, 
        i.tax_amount, 
        i.total_amount,
        i.payment_status,
        i.payment_method,
        i.notes,
        i.created_at,
        u.username as created_by_username,
        u.full_name as created_by_name
      FROM 
        invoices i
        LEFT JOIN users u ON i.created_by = u.id
      WHERE 
        i.type = 'resort'
        AND i.invoice_date BETWEEN ? AND ?
        ${guestWhereCondition}
      ORDER BY 
        i.invoice_date ASC
    `;
    
    // Prepare parameters for the invoice query
    const invoiceParams = guest_name 
      ? [formattedFromDate, formattedToDate, `%${guest_name}%`] 
      : [formattedFromDate, formattedToDate];
    
    const [invoices] = await pool.query(invoiceQuery, invoiceParams);
    
    if (invoices.length === 0) {
      return res.status(404).json({ 
        status: 'error', 
        message: 'No resort invoices found for the given date range and guest name' 
      });
    }
    
    // Get invoice items for all the invoices
    const invoiceIds = invoices.map(inv => inv.id);
    
    const itemsQuery = `
      SELECT 
        ii.id,
        ii.invoice_id, 
        ii.item_id, 
        ii.service_id,
        ii.item_name, 
        ii.quantity, 
        ii.rate, 
        ii.gst_percentage, 
        ii.gst_amount, 
        ii.total,
        ii.booking_date,
        CASE 
          WHEN ii.item_id IS NOT NULL THEN 'menu_item'
          WHEN ii.service_id IS NOT NULL THEN 'service'
          ELSE 'other'
          END as item_type
      FROM 
        invoice_items ii
      WHERE 
        ii.invoice_id IN (?)
      ORDER BY 
        ii.booking_date ASC, ii.invoice_id ASC
    `;
    
    const [items] = await pool.query(itemsQuery, [invoiceIds]);
    
    // Get resort information for the invoice header
    const [resortInfo] = await pool.query('SELECT * FROM settings LIMIT 1');
    
    // Group invoice items by invoice
    const invoiceItemsMap = items.reduce((acc, item) => {
      if (!acc[item.invoice_id]) {
        acc[item.invoice_id] = [];
      }
      acc[item.invoice_id].push(item);
      return acc;
    }, {});
    
    // Attach items to their respective invoices
    invoices.forEach(invoice => {
      invoice.items = invoiceItemsMap[invoice.id] || [];
    });
    
    // Calculate aggregated totals
    const aggregatedData = {
      resort_info: resortInfo[0],
      date_range: {
        from_date: from_date,
        to_date: to_date
      },
      guest_filter: guest_name || 'All Guests',
      invoices: invoices,
      summary: {
        total_invoices: invoices.length,
        total_subtotal: 0,
        total_tax: 0,
        total_amount: 0,
        payment_status_summary: {
          paid: 0,
          pending: 0,
          cancelled: 0
        },
        payment_method_summary: {
          cash: 0,
          card: 0,
          upi: 0,
          other: 0
        }
      }
    };
    
    // Calculate summary totals
    invoices.forEach(invoice => {
      aggregatedData.summary.total_subtotal += parseFloat(invoice.subtotal);
      aggregatedData.summary.total_tax += parseFloat(invoice.tax_amount);
      aggregatedData.summary.total_amount += parseFloat(invoice.total_amount);
      
      // Count by payment status
      if (invoice.payment_status) {
        aggregatedData.summary.payment_status_summary[invoice.payment_status]++;
      }
      
      // Count by payment method
      if (invoice.payment_method) {
        aggregatedData.summary.payment_method_summary[invoice.payment_method]++;
      }
    });
    
    res.json({
      status: 'success',
      data: aggregatedData
    });
    
  } catch (error) {
    console.error('Error generating aggregated resort invoice:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to generate aggregated resort invoice', 
      error: error.message 
    });
  }
});

app.get('/api/invoices/aggregated/kitchen', async (req, res) => {
  try {
    const { from_date, to_date, guest_name } = req.query;
    
    if (!from_date || !to_date) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'Both from_date and to_date are required' 
      });
    }

    // Format dates for query
    const formattedFromDate = new Date(from_date).toISOString().split('T')[0];
    const formattedToDate = new Date(to_date).toISOString().split('T')[0] + ' 23:59:59';

    // Base query parts
    let guestWhereCondition = '';
    
    if (guest_name) {
      guestWhereCondition = 'AND i.guest_name LIKE ?';
    }

    // Get kitchen invoices
    const invoiceQuery = `
      SELECT 
        i.id, 
        i.invoice_number, 
        i.invoice_date, 
        i.guest_id,
        i.room_number,
        i.guest_name, 
        i.guest_mobile,
        i.subtotal, 
        i.tax_amount, 
        i.total_amount,
        i.payment_status,
        i.payment_method,
        i.notes,
        i.created_at,
        u.username as created_by_username,
        u.full_name as created_by_name,
        ko.order_number,
        ko.order_type
      FROM 
        invoices i
        LEFT JOIN users u ON i.created_by = u.id
        LEFT JOIN kitchen_orders ko ON i.id = ko.invoice_id
      WHERE 
        i.type = 'kitchen'
        AND i.invoice_date BETWEEN ? AND ?
        ${guestWhereCondition}
      ORDER BY 
        i.invoice_date ASC
    `;
    
    // Prepare parameters for the invoice query
    const invoiceParams = guest_name 
      ? [formattedFromDate, formattedToDate, `%${guest_name}%`] 
      : [formattedFromDate, formattedToDate];
    
    const [invoices] = await pool.query(invoiceQuery, invoiceParams);
    
    if (invoices.length === 0) {
      return res.status(404).json({ 
        status: 'error', 
        message: 'No kitchen invoices found for the given date range and guest name' 
      });
    }
    
    // Get invoice items for all the invoices
    const invoiceIds = invoices.map(inv => inv.id);
    
    const itemsQuery = `
      SELECT 
        ii.id,
        ii.invoice_id, 
        ii.item_id, 
        ii.item_name, 
        ii.quantity, 
        ii.rate, 
        ii.gst_percentage, 
        ii.gst_amount, 
        ii.total,
        ii.booking_date,
        'menu_item' as item_type,
        mi.description as item_description
      FROM 
        invoice_items ii
        LEFT JOIN menu_items mi ON ii.item_id = mi.id
      WHERE 
        ii.invoice_id IN (?)
      ORDER BY 
        ii.booking_date ASC, ii.invoice_id ASC
    `;
    
    const [items] = await pool.query(itemsQuery, [invoiceIds]);
    
    // Get kitchen information for the invoice header
    const [kitchenInfo] = await pool.query('SELECT * FROM settings LIMIT 1');
    
    // Group invoice items by invoice
    const invoiceItemsMap = items.reduce((acc, item) => {
      if (!acc[item.invoice_id]) {
        acc[item.invoice_id] = [];
      }
      acc[item.invoice_id].push(item);
      return acc;
    }, {});
    
    // Attach items to their respective invoices
    invoices.forEach(invoice => {
      invoice.items = invoiceItemsMap[invoice.id] || [];
    });
    
    // Calculate aggregated totals
    const aggregatedData = {
      kitchen_info: kitchenInfo[0],
      date_range: {
        from_date: from_date,
        to_date: to_date
      },
      guest_filter: guest_name || 'All Guests',
      invoices: invoices,
      summary: {
        total_invoices: invoices.length,
        total_subtotal: 0,
        total_tax: 0,
        total_amount: 0,
        order_type_summary: {
          room: 0,
          walk_in: 0
        },
        payment_status_summary: {
          paid: 0,
          pending: 0,
          cancelled: 0
        },
        payment_method_summary: {
          cash: 0,
          card: 0,
          upi: 0,
          other: 0
        }
      }
    };
    
    // Calculate summary totals
    invoices.forEach(invoice => {
      aggregatedData.summary.total_subtotal += parseFloat(invoice.subtotal);
      aggregatedData.summary.total_tax += parseFloat(invoice.tax_amount);
      aggregatedData.summary.total_amount += parseFloat(invoice.total_amount);
      
      // Count by order type
      if (invoice.order_type) {
        aggregatedData.summary.order_type_summary[invoice.order_type]++;
      }
      
      // Count by payment status
      if (invoice.payment_status) {
        aggregatedData.summary.payment_status_summary[invoice.payment_status]++;
      }
      
      // Count by payment method
      if (invoice.payment_method) {
        aggregatedData.summary.payment_method_summary[invoice.payment_method]++;
      }
    });
    
    res.json({
      status: 'success',
      data: aggregatedData
    });
    
  } catch (error) {
    console.error('Error generating aggregated kitchen invoice:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to generate aggregated kitchen invoice', 
      error: error.message 
    });
  }
});

app.delete('/api/invoices/:id', authenticateToken, async (req, res) => {
  try {
    const invoiceId = req.params.id;
    
    // Check if invoice exists
    const [invoiceCheck] = await pool.query(
      'SELECT id FROM invoices WHERE id = ?',
      [invoiceId]
    );
    
    if (invoiceCheck.length === 0) {
      return res.status(404).json({ message: 'Invoice not found' });
    }
    
    // Begin transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      // Delete invoice items first (due to foreign key constraint)
      await connection.query(
        'DELETE FROM invoice_items WHERE invoice_id = ?',
        [invoiceId]
      );
      
      // Delete the invoice
      const [result] = await connection.query(
        'DELETE FROM invoices WHERE id = ?',
        [invoiceId]
      );
      
      // Commit transaction
      await connection.commit();
      connection.release();
      
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'Invoice not found' });
      }
      
      res.status(200).json({ message: 'Invoice deleted successfully' });
    } catch (error) {
      // Rollback transaction on error
      await connection.rollback();
      connection.release();
      throw error;
    }
  } catch (error) {
    console.error('Error deleting invoice:', error);
    res.status(500).json({ message: 'Server error' });
  }
});



app.get('/api/reports/resort-details', async (req, res) => {
  try {
    // Create a new Excel workbook
    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'Resort Management System';
    workbook.lastModifiedBy = 'Resort Management System';
    workbook.created = new Date();
    workbook.modified = new Date();
    
    // Connect to the database
    const connection = await pool.getConnection();
    
    try {
      // Get resort settings
      const [settingsRows] = await connection.query('SELECT * FROM settings LIMIT 1');
      const resortSettings = settingsRows[0];
      
      // Create Resort Info worksheet
      const resortInfoSheet = workbook.addWorksheet('Resort Info');
      resortInfoSheet.columns = [
        { header: 'Property', key: 'property', width: 25 },
        { header: 'Value', key: 'value', width: 50 }
      ];
      
      // Add resort info data
      resortInfoSheet.addRows([
        { property: 'Resort Name', value: resortSettings.resort_name },
        { property: 'Resort GSTIN', value: resortSettings.resort_gstin },
        { property: 'Kitchen GSTIN', value: resortSettings.kitchen_gstin },
        { property: 'Address', value: resortSettings.resort_address },
        { property: 'Contact', value: resortSettings.resort_contact },
        { property: 'Email', value: resortSettings.resort_email },
        { property: 'Tax Rate', value: `${resortSettings.tax_rate}%` }
      ]);
      
      // Format the headers
      resortInfoSheet.getRow(1).font = { bold: true };
      resortInfoSheet.getRow(1).fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFD3D3D3' }
      };
      
      // Get menu items
      const [menuItems] = await connection.query('SELECT * FROM menu_items ORDER BY type, name');
      
      // Create Menu Items worksheet
      const menuItemsSheet = workbook.addWorksheet('Menu Items');
      menuItemsSheet.columns = [
        { header: 'ID', key: 'id', width: 10 },
        { header: 'Name', key: 'name', width: 30 },
        { header: 'Description', key: 'description', width: 50 },
        { header: 'Price (₹)', key: 'price', width: 15 },
        { header: 'GST %', key: 'gst_percentage', width: 15 },
        { header: 'Type', key: 'type', width: 15 },
        { header: 'Status', key: 'status', width: 15 }
      ];
      
      // Add menu items data
      menuItems.forEach(item => {
        menuItemsSheet.addRow({
          id: item.id,
          name: item.name,
          description: item.description,
          price: item.price,
          gst_percentage: `${item.gst_percentage}%`,
          type: item.type,
          status: item.is_active ? 'Active' : 'Inactive'
        });
      });
      
      // Format the headers
      menuItemsSheet.getRow(1).font = { bold: true };
      menuItemsSheet.getRow(1).fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFD3D3D3' }
      };
      
      // Get services
      const [services] = await connection.query('SELECT * FROM services ORDER BY name');
      
      // Create Services worksheet
      const servicesSheet = workbook.addWorksheet('Services');
      servicesSheet.columns = [
        { header: 'ID', key: 'id', width: 10 },
        { header: 'Name', key: 'name', width: 30 },
        { header: 'Description', key: 'description', width: 50 },
        { header: 'Price (₹)', key: 'price', width: 15 },
        { header: 'GST %', key: 'gst_percentage', width: 15 },
        { header: 'Status', key: 'status', width: 15 }
      ];
      
      // Add services data
      services.forEach(service => {
        servicesSheet.addRow({
          id: service.id,
          name: service.name,
          description: service.description,
          price: service.price,
          gst_percentage: `${service.gst_percentage}%`,
          status: service.is_active ? 'Active' : 'Inactive'
        });
      });
      
      // Format the headers
      servicesSheet.getRow(1).font = { bold: true };
      servicesSheet.getRow(1).fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFD3D3D3' }
      };
      
      // Get current guests
      const [guests] = await connection.query('SELECT * FROM guests WHERE is_checked_out = 0 ORDER BY room_number');
      
      // Create Current Guests worksheet
      const guestsSheet = workbook.addWorksheet('Current Guests');
      guestsSheet.columns = [
        { header: 'ID', key: 'id', width: 10 },
        { header: 'Name', key: 'name', width: 30 },
        { header: 'Room', key: 'room_number', width: 15 },
        { header: 'Mobile', key: 'mobile', width: 20 },
        { header: 'Email', key: 'email', width: 30 },
        { header: 'Check In', key: 'check_in_date', width: 20 },
        { header: 'Check Out', key: 'check_out_date', width: 20 }
      ];
      
      // Add guests data
      guests.forEach(guest => {
        guestsSheet.addRow({
          id: guest.id,
          name: guest.name,
          room_number: guest.room_number,
          mobile: guest.mobile,
          email: guest.email,
          check_in_date: guest.check_in_date ? new Date(guest.check_in_date) : null,
          check_out_date: guest.check_out_date ? new Date(guest.check_out_date) : null
        });
      });
      
      // Format the headers
      guestsSheet.getRow(1).font = { bold: true };
      guestsSheet.getRow(1).fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFD3D3D3' }
      };
      
      // Get recent invoices (last 30 days)
      const [invoices] = await connection.query(
        'SELECT * FROM invoices WHERE invoice_date >= DATE_SUB(NOW(), INTERVAL 30 DAY) ORDER BY invoice_date DESC'
      );
      
      // Create Recent Invoices worksheet
      const invoicesSheet = workbook.addWorksheet('Recent Invoices');
      invoicesSheet.columns = [
        { header: 'Invoice #', key: 'invoice_number', width: 20 },
        { header: 'Date', key: 'invoice_date', width: 20 },
        { header: 'Guest', key: 'guest_name', width: 30 },
        { header: 'Room', key: 'room_number', width: 15 },
        { header: 'Type', key: 'type', width: 15 },
        { header: 'Subtotal (₹)', key: 'subtotal', width: 15 },
        { header: 'Tax (₹)', key: 'tax_amount', width: 15 },
        { header: 'Total (₹)', key: 'total_amount', width: 15 },
        { header: 'Status', key: 'payment_status', width: 15 }
      ];
      
      // Add invoices data
      invoices.forEach(invoice => {
        invoicesSheet.addRow({
          invoice_number: invoice.invoice_number,
          invoice_date: new Date(invoice.invoice_date),
          guest_name: invoice.guest_name,
          room_number: invoice.room_number,
          type: invoice.type,
          subtotal: invoice.subtotal,
          tax_amount: invoice.tax_amount,
          total_amount: invoice.total_amount,
          payment_status: invoice.payment_status
        });
      });
      
      // Format the headers
      invoicesSheet.getRow(1).font = { bold: true };
      invoicesSheet.getRow(1).fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFD3D3D3' }
      };
      
      // Get users
      const [users] = await connection.query('SELECT id, username, full_name, email, role, created_at FROM users');
      
      // Create Users worksheet
      const usersSheet = workbook.addWorksheet('Users');
      usersSheet.columns = [
        { header: 'ID', key: 'id', width: 10 },
        { header: 'Username', key: 'username', width: 20 },
        { header: 'Full Name', key: 'full_name', width: 30 },
        { header: 'Email', key: 'email', width: 30 },
        { header: 'Role', key: 'role', width: 15 },
        { header: 'Created At', key: 'created_at', width: 20 }
      ];
      
      // Add users data (excluding password)
      users.forEach(user => {
        usersSheet.addRow({
          id: user.id,
          username: user.username,
          full_name: user.full_name,
          email: user.email,
          role: user.role,
          created_at: new Date(user.created_at)
        });
      });
      
      // Format the headers
      usersSheet.getRow(1).font = { bold: true };
      usersSheet.getRow(1).fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFD3D3D3' }
      };
      
      // Generate filename based on date
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `Resort_Details_${timestamp}.xlsx`;
      const filePath = path.join(excelReportsDir, filename);
      
      // Write to file
      await workbook.xlsx.writeFile(filePath);
      
      // Send file as download
      res.download(filePath, filename, (err) => {
        if (err) {
          console.error('Error downloading file:', err);
          // Don't delete the file if there was an error sending it
        } else {
          // Optionally delete the file after sending
          // Uncomment the next line if you want to delete the file after download
          // fs.unlinkSync(filePath);
        }
      });
    } finally {
      // Release the connection back to the pool
      connection.release();
    }
  } catch (error) {
    console.error('Error generating Excel report:', error);
    res.status(500).json({ success: false, message: 'Error generating Excel report', error: error.message });
  }
});


app.get('/api/reports/sales/excel', async (req, res) => {
  try {
    const { start_date, end_date, type } = req.query;
    
    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Start date and end date are required' });
    }
    
    let query = `
      SELECT 
        DATE(invoice_date) as date,
        type,
        COUNT(*) as invoice_count,
        SUM(subtotal) as subtotal,
        SUM(tax_amount) as tax_amount,
        SUM(total_amount) as total_amount
      FROM invoices
      WHERE invoice_date >= ? AND invoice_date <= ?
    `;
    
    let params = [start_date, end_date + ' 23:59:59'];
    
    if (type) {
      query += ' AND type = ?';
      params.push(type);
    }
    
    query += ' GROUP BY DATE(invoice_date), type ORDER BY date';
    
    const [results] = await pool.query(query, params);
    
    // Format the data for Excel
    const dailyData = results.map(row => ({
      Date: row.date,
      Type: row.type,
      'Invoice Count': row.invoice_count,
      'Subtotal': Number(row.subtotal || 0).toFixed(2),
      'Tax Amount': Number(row.tax_amount || 0).toFixed(2),
      'Total Amount': Number(row.total_amount || 0).toFixed(2)
    }));
    
    // Calculate summary row
    const summary = {
      Date: 'TOTAL',
      Type: '',
      'Invoice Count': 0,
      'Subtotal': 0,
      'Tax Amount': 0,
      'Total Amount': 0
    };
    
    results.forEach(row => {
      summary['Invoice Count'] += Number(row.invoice_count || 0);
      summary['Subtotal'] += Number(row.subtotal || 0);
      summary['Tax Amount'] += Number(row.tax_amount || 0);
      summary['Total Amount'] += Number(row.total_amount || 0);
    });
    
    summary['Subtotal'] = Number(summary['Subtotal'] || 0).toFixed(2);
    summary['Tax Amount'] = Number(summary['Tax Amount'] || 0).toFixed(2);
    summary['Total Amount'] = Number(summary['Total Amount'] || 0).toFixed(2);
    
    // Add summary row to the end
    dailyData.push(summary);
    
    // Create workbook and worksheet
    const wb = xlsx.utils.book_new();
    const ws = xlsx.utils.json_to_sheet(dailyData);
    
    // Add title rows with report details
    xlsx.utils.sheet_add_aoa(ws, [
      [`Sales Report (${start_date} to ${end_date})`],
      [''],  // Empty row for spacing
    ], { origin: 'A1' });
    
    // Add the worksheet to the workbook
    xlsx.utils.book_append_sheet(wb, ws, 'Sales Report');
    
    // Set column widths
    const cols = [
      { wch: 12 },  // Date
      { wch: 10 },  // Type
      { wch: 15 },  // Invoice Count
      { wch: 15 },  // Subtotal
      { wch: 15 },  // Tax Amount
      { wch: 15 },  // Total Amount
    ];
    ws['!cols'] = cols;
    
    // Generate Excel file
    const excelBuffer = xlsx.write(wb, { bookType: 'xlsx', type: 'buffer' });
    
    // Set response headers for file download
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename=sales_report_${start_date}_to_${end_date}.xlsx`);
    res.setHeader('Content-Length', excelBuffer.length);
    
    // Send the file
    res.send(excelBuffer);
  } catch (error) {
    console.error('Error generating sales excel report:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Excel report generation for GST data
app.get('/api/reports/gst/excel', async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Start date and end date are required' });
    }
    
    const query = `
      SELECT 
        type,
        SUM(subtotal) as taxable_amount,
        SUM(tax_amount) as tax_amount,
        SUM(total_amount) as total_amount
      FROM invoices
      WHERE invoice_date >= ? AND invoice_date <= ?
      GROUP BY type
    `;
    
    const [results] = await pool.query(query, [start_date, end_date + ' 23:59:59']);
    
    // Get GSTIN information
    const [settings] = await pool.query('SELECT resort_gstin, kitchen_gstin FROM settings LIMIT 1');
    
    // Format the data for Excel
    const reportData = [];
    let resortData = null;
    let kitchenData = null;
    
    results.forEach(row => {
      if (row.type === 'resort') {
        resortData = row;
      } else if (row.type === 'kitchen') {
        kitchenData = row;
      }
    });
    
    // Resort data
    if (resortData) {
      reportData.push({
        'Business Type': 'Resort',
        'GSTIN': settings[0].resort_gstin || 'N/A',
        'Taxable Amount': Number(resortData.taxable_amount || 0).toFixed(2),
        'Tax Amount': Number(resortData.tax_amount || 0).toFixed(2),
        'Total Amount': Number(resortData.total_amount || 0).toFixed(2)
      });
    } else {
      reportData.push({
        'Business Type': 'Resort',
        'GSTIN': settings[0].resort_gstin || 'N/A',
        'Taxable Amount': '0.00',
        'Tax Amount': '0.00',
        'Total Amount': '0.00'
      });
    }
    
    // Kitchen data
    if (kitchenData) {
      reportData.push({
        'Business Type': 'Kitchen',
        'GSTIN': settings[0].kitchen_gstin || 'N/A',
        'Taxable Amount': Number(kitchenData.taxable_amount || 0).toFixed(2),
        'Tax Amount': Number(kitchenData.tax_amount || 0).toFixed(2),
        'Total Amount': Number(kitchenData.total_amount || 0).toFixed(2)
      });
    } else {
      reportData.push({
        'Business Type': 'Kitchen',
        'GSTIN': settings[0].kitchen_gstin || 'N/A',
        'Taxable Amount': '0.00',
        'Tax Amount': '0.00',
        'Total Amount': '0.00'
      });
    }
    
    // Calculate totals
    let totalTaxable = 0;
    let totalTax = 0;
    let totalAmount = 0;
    
    results.forEach(row => {
      if (row.type === 'resort') {
        totalTaxable += Number(row.taxable_amount || 0);
        totalTax += Number(row.tax_amount || 0);
        totalAmount += Number(row.total_amount || 0);
      } else if (row.type === 'kitchen') {
        totalTaxable += Number(row.taxable_amount || 0);
        totalTax += Number(row.tax_amount || 0);
        totalAmount += Number(row.total_amount || 0);
      }
    });
    
    // Add total row
    reportData.push({
      'Business Type': 'TOTAL',
      'GSTIN': '',
      'Taxable Amount': Number(totalTaxable || 0).toFixed(2),
      'Tax Amount': Number(totalTax || 0).toFixed(2),
      'Total Amount': Number(totalAmount || 0).toFixed(2)
    });
    
    // Create workbook and worksheet
    const wb = xlsx.utils.book_new();
    const ws = xlsx.utils.json_to_sheet(reportData);
    
    // Add title rows with report details
    xlsx.utils.sheet_add_aoa(ws, [
      [`GST Report (${start_date} to ${end_date})`],
      [''],  // Empty row for spacing
    ], { origin: 'A1' });
    
    // Add the worksheet to the workbook
    xlsx.utils.book_append_sheet(wb, ws, 'GST Report');
    
    // Set column widths
    const cols = [
      { wch: 15 },  // Business Type
      { wch: 20 },  // GSTIN
      { wch: 15 },  // Taxable Amount
      { wch: 15 },  // Tax Amount
      { wch: 15 },  // Total Amount
    ];
    ws['!cols'] = cols;
    
    // Generate Excel file
    const excelBuffer = xlsx.write(wb, { bookType: 'xlsx', type: 'buffer' });
    
    // Set response headers for file download
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename=gst_report_${start_date}_to_${end_date}.xlsx`);
    res.setHeader('Content-Length', excelBuffer.length);
    
    // Send the file
    res.send(excelBuffer);
  } catch (error) {
    console.error('Error generating GST excel report:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Excel report generation for kitchen items data
app.get('/api/reports/kitchen-items/excel', async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    
    if (!start_date || !end_date) {
      return res.status(400).json({ message: 'Start date and end date are required' });
    }
    
    const query = `
      SELECT 
        mi.id,
        mi.name,
        SUM(koi.quantity) as total_quantity,
        SUM(koi.total) as total_amount
      FROM kitchen_order_items koi
      JOIN menu_items mi ON koi.item_id = mi.id
      JOIN kitchen_orders ko ON koi.order_id = ko.id
      WHERE ko.order_date >= ? AND ko.order_date <= ?
      GROUP BY mi.id, mi.name
      ORDER BY total_quantity DESC
    `;
    
    const [results] = await pool.query(query, [start_date, end_date + ' 23:59:59']);
    
    // Format the data for Excel
    const itemsData = results.map((row, index) => ({
      'Sl No': index + 1,
      'Item Name': row.name,
      'Quantity Sold': Number(row.total_quantity || 0),
      'Total Sales Amount': Number(row.total_amount || 0).toFixed(2)
    }));
    
    // Calculate totals
    let totalQuantity = 0;
    let totalAmount = 0;
    
    results.forEach(row => {
      totalQuantity += Number(row.total_quantity || 0);
      totalAmount += Number(row.total_amount || 0);
    });
    
    // Add total row
    itemsData.push({
      'Sl No': '',
      'Item Name': 'TOTAL',
      'Quantity Sold': Number(totalQuantity || 0),
      'Total Sales Amount': Number(totalAmount || 0).toFixed(2)
    });
    
    // Create workbook and worksheet
    const wb = xlsx.utils.book_new();
    const ws = xlsx.utils.json_to_sheet(itemsData);
    
    // Add title rows with report details
    xlsx.utils.sheet_add_aoa(ws, [
      [`Kitchen Items Report (${start_date} to ${end_date})`],
      [''],  // Empty row for spacing
    ], { origin: 'A1' });
    
    // Add the worksheet to the workbook
    xlsx.utils.book_append_sheet(wb, ws, 'Kitchen Items Report');
    
    // Set column widths
    const cols = [
      { wch: 8 },   // Sl No
      { wch: 30 },  // Item Name
      { wch: 15 },  // Quantity Sold
      { wch: 20 },  // Total Sales Amount
    ];
    ws['!cols'] = cols;
    
    // Generate Excel file
    const excelBuffer = xlsx.write(wb, { bookType: 'xlsx', type: 'buffer' });
    
    // Set response headers for file download
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename=kitchen_items_report_${start_date}_to_${end_date}.xlsx`);
    res.setHeader('Content-Length', excelBuffer.length);
    
    // Send the file
    res.send(excelBuffer);
  } catch (error) {
    console.error('Error generating kitchen items excel report:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


app.get("/api/logo",(req,res)=>{

  res.sendFile(path.join(__dirname,"logo.png"));
})
app.get("/api/logo/footer",(req,res)=>{

  res.sendFile(path.join(__dirname,"logo2.jpg"));
})




app.post('/api/invoices/aggregated/resort/email', async (req, res) => {
  try {
    const { from_date, to_date, guest_name, email_to } = req.query;
    
    // Validate required parameters
    if (!from_date || !to_date) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'Both from_date and to_date are required' 
      });
    }

    if (!email_to) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'Email address is required' 
      });
    }

    // Format dates for query
    const formattedFromDate = new Date(from_date).toISOString().split('T')[0];
    const formattedToDate = new Date(to_date).toISOString().split('T')[0] + ' 23:59:59';

    // Base query parts
    let guestWhereCondition = '';
    
    if (guest_name) {
      guestWhereCondition = 'AND i.guest_name LIKE ?';
    }

    // Get resort invoices
    const invoiceQuery = `
      SELECT 
        i.id, 
        i.invoice_number, 
        i.invoice_date, 
        i.guest_id,
        i.room_number,
        i.guest_name, 
        i.guest_mobile,
        i.subtotal, 
        i.tax_amount, 
        i.total_amount,
        i.payment_status,
        i.payment_method,
        i.notes,
        i.created_at,
        u.username as created_by_username,
        u.full_name as created_by_name
      FROM 
        invoices i
        LEFT JOIN users u ON i.created_by = u.id
      WHERE 
        i.type = 'resort'
        AND i.invoice_date BETWEEN ? AND ?
        ${guestWhereCondition}
      ORDER BY 
        i.invoice_date ASC
    `;
    
    // Prepare parameters for the invoice query
    const invoiceParams = guest_name 
      ? [formattedFromDate, formattedToDate, `%${guest_name}%`] 
      : [formattedFromDate, formattedToDate];
    
    const [invoices] = await pool.query(invoiceQuery, invoiceParams);
    
    if (invoices.length === 0) {
      return res.status(404).json({ 
        status: 'error', 
        message: 'No resort invoices found for the given date range and guest name' 
      });
    }
    
    // Get invoice items for all the invoices
    const invoiceIds = invoices.map(inv => inv.id);
    
    const itemsQuery = `
      SELECT 
        ii.id,
        ii.invoice_id, 
        ii.item_id, 
        ii.service_id,
        ii.item_name, 
        ii.quantity, 
        ii.rate, 
        ii.gst_percentage, 
        ii.gst_amount, 
        ii.total,
        ii.booking_date,
        CASE 
          WHEN ii.item_id IS NOT NULL THEN 'menu_item'
          WHEN ii.service_id IS NOT NULL THEN 'service'
          ELSE 'other'
          END as item_type
      FROM 
        invoice_items ii
      WHERE 
        ii.invoice_id IN (?)
      ORDER BY 
        ii.booking_date ASC, ii.invoice_id ASC
    `;
    
    const [items] = await pool.query(itemsQuery, [invoiceIds]);
    
    // Get resort information for the invoice header
    const [resortInfo] = await pool.query('SELECT * FROM settings LIMIT 1');
    
    // Group invoice items by invoice
    const invoiceItemsMap = items.reduce((acc, item) => {
      if (!acc[item.invoice_id]) {
        acc[item.invoice_id] = [];
      }
      acc[item.invoice_id].push(item);
      return acc;
    }, {});
    
    // Attach items to their respective invoices
    invoices.forEach(invoice => {
      invoice.items = invoiceItemsMap[invoice.id] || [];
    });
    
    // Calculate aggregated totals
    const aggregatedData = {
      resort_info: resortInfo[0],
      date_range: {
        from_date: from_date,
        to_date: to_date
      },
      guest_filter: guest_name || 'All Guests',
      invoices: invoices,
      summary: {
        total_invoices: invoices.length,
        total_subtotal: 0,
        total_tax: 0,
        total_amount: 0,
        payment_status_summary: {
          paid: 0,
          pending: 0,
          cancelled: 0
        },
        payment_method_summary: {
          cash: 0,
          card: 0,
          upi: 0,
          other: 0
        }
      }
    };
    
    // Calculate summary totals
    invoices.forEach(invoice => {
      aggregatedData.summary.total_subtotal += parseFloat(invoice.subtotal);
      aggregatedData.summary.total_tax += parseFloat(invoice.tax_amount);
      aggregatedData.summary.total_amount += parseFloat(invoice.total_amount);
      
      // Count by payment status
      if (invoice.payment_status) {
        const status = invoice.payment_status.toLowerCase();
        if (!aggregatedData.summary.payment_status_summary[status]) {
          aggregatedData.summary.payment_status_summary[status] = 0;
        }
        aggregatedData.summary.payment_status_summary[status]++;
      }
      
      // Count by payment method
      if (invoice.payment_method) {
        const method = invoice.payment_method.toLowerCase();
        if (!aggregatedData.summary.payment_method_summary[method]) {
          aggregatedData.summary.payment_method_summary[method] = 0;
        }
        aggregatedData.summary.payment_method_summary[method]++;
      }
    });

    // Generate HTML email content
    const emailContent = generateInvoiceEmailHTML(aggregatedData);
    
    // Generate PDF attachment (assuming you have a PDF generation library)
    const pdfBuffer = await generateInvoicePDF(aggregatedData);
    
    const mailOptions = {
      from: `"${resortInfo[0].resort_name}" <${process.env.EMAIL_USER}>`,
      to: email_to,
      subject: `Resort Invoice Report (${from_date} to ${to_date})`,
      html: emailContent,
      attachments: [
        {
          filename: `invoice_report_${from_date}_to_${to_date}.pdf`,
          content: pdfBuffer,
          contentType: 'application/pdf'
        }
      ]
    };
    
    // Send email
    const info = await transporter.sendMail(mailOptions);
    
    res.json({
      status: 'success',
      message: 'Invoice report has been sent to the specified email',
      email_details: {
        messageId: info.messageId,
        recipient: email_to
      }
    });
    
  } catch (error) {
    console.error('Error sending invoice email:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to send invoice email', 
      error: error.message 
    });
  }
});

/**
 * Generate HTML content for invoice email
 * @param {Object} data - Aggregated invoice data
 * @returns {String} HTML content
 */
function generateInvoiceEmailHTML(data) {
  const { resort_info, date_range, guest_filter, summary } = data;
  
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; }
        .resort-name { font-size: 24px; font-weight: bold; margin-bottom: 5px; }
        .report-title { font-size: 18px; margin-bottom: 20px; }
        .section { margin-bottom: 25px; }
        .summary-box { background-color: #f9f9f9; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .footer { margin-top: 30px; font-size: 12px; color: #666; text-align: center; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <div class="resort-name">${resort_info.resort_name}</div>
          <div>${resort_info.resort_address}</div>
          <div>Phone: ${resort_info.resort_contact}</div>
          <div>Email: ${resort_info.resort_email}</div>
          <div>GSTIN (Resort): ${resort_info.resort_gstin}</div>
          <div>GSTIN (Kitchen): ${resort_info.kitchen_gstin}</div>
        </div>
        
        <div class="report-title">
          <h2>Invoice Report Summary</h2>
          <p>Date Range: ${date_range.from_date} to ${date_range.to_date}</p>
          <p>Guest Filter: ${guest_filter}</p>
        </div>
        
        <div class="section">
          <div class="summary-box">
            <h3>Summary</h3>
            <p>Total Invoices: ${summary.total_invoices}</p>
            <p>Total Amount (before tax): ${summary.total_subtotal.toFixed(2)}</p>
            <p>Total Tax: ${summary.total_tax.toFixed(2)}</p>
            <p>Total Amount (including tax): ${summary.total_amount.toFixed(2)}</p>
          </div>
        </div>
        
        <div class="section">
          <h3>Payment Status Summary</h3>
          <table>
            <tr>
              <th>Status</th>
              <th>Count</th>
            </tr>
            ${Object.entries(summary.payment_status_summary).map(([status, count]) => `
              <tr>
                <td>${status.charAt(0).toUpperCase() + status.slice(1)}</td>
                <td>${count}</td>
              </tr>
            `).join('')}
          </table>
        </div>
        
        <div class="section">
          <h3>Payment Method Summary</h3>
          <table>
            <tr>
              <th>Method</th>
              <th>Count</th>
            </tr>
            ${Object.entries(summary.payment_method_summary).map(([method, count]) => `
              <tr>
                <td>${method.charAt(0).toUpperCase() + method.slice(1)}</td>
                <td>${count}</td>
              </tr>
            `).join('')}
          </table>
        </div>
        
        <div class="footer">
          <p>Please see the attached PDF for detailed invoice information.</p>
          <p>This is an automated email from ${resort_info.resort_name}.</p>
        </div>
      </div>
    </body>
    </html>
  `;
}

/**
 * Generate PDF for invoice report
 * @param {Object} data - Aggregated invoice data
 * @returns {Buffer} PDF buffer
 */
async function generateInvoicePDF(data) {
  // This is just a placeholder function. You'll need to implement PDF generation
  // with a library like PDFKit, html-pdf, puppeteer, etc.
  
  // Example implementation with PDFKit
  // const PDFDocument = require('pdfkit');

  // const fs = require('fs');
  
  return new Promise((resolve, reject) => {
    try {
      const { resort_info, date_range, guest_filter, invoices, summary } = data;
      
      // Create a document
      const doc = new PDFDocument({ margin: 50 });
      const chunks = [];
      
      doc.on('data', chunk => chunks.push(chunk));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      
      // Add resort header
      doc.fontSize(20).text(resort_info.resort_name, { align: 'center' });
      doc.fontSize(12).text(resort_info.resort_address, { align: 'center' });
      doc.text('GSTIN (Resort): ' + resort_info.resort_gstin, { align: 'center' });
      doc.text('GSTIN (Kitchen): ' + resort_info.kitchen_gstin, { align: 'center' });
      doc.text('Phone: ' + resort_info.resort_contact, { align: 'center' });
      doc.text('Email: ' + resort_info.resort_email, { align: 'center' });
      doc.moveDown(2);
      
      // Add report title
      doc.fontSize(16).text('Invoice Report', { align: 'center' });
      doc.fontSize(12).text(`Date Range: ${date_range.from_date} to ${date_range.to_date}`, { align: 'center' });
      doc.text(`Guest Filter: ${guest_filter}`, { align: 'center' });
      doc.moveDown(2);
      
      // Add summary
      doc.fontSize(14).text('Summary', { underline: true });
      doc.fontSize(12).text(`Total Invoices: ${summary.total_invoices}`);
      doc.text(`Total Amount (before tax): ${summary.total_subtotal.toFixed(2)}`);
      doc.text(`Total Tax: ${summary.total_tax.toFixed(2)}`);
      doc.text(`Total Amount (including tax): ${summary.total_amount.toFixed(2)}`);
      doc.moveDown();
      
      // Add payment status summary
      doc.fontSize(14).text('Payment Status Summary', { underline: true });
      Object.entries(summary.payment_status_summary).forEach(([status, count]) => {
        doc.fontSize(12).text(`${status.charAt(0).toUpperCase() + status.slice(1)}: ${count}`);
      });
      doc.moveDown();
      
      // Add payment method summary
      doc.fontSize(14).text('Payment Method Summary', { underline: true });
      Object.entries(summary.payment_method_summary).forEach(([method, count]) => {
        doc.fontSize(12).text(`${method.charAt(0).toUpperCase() + method.slice(1)}: ${count}`);
      });
      doc.moveDown(2);
      
      // Add detailed invoices
      doc.fontSize(16).text('Detailed Invoices', { underline: true });
      
      invoices.forEach((invoice, index) => {
        if (index > 0) doc.addPage();
        
        doc.fontSize(14).text(`Invoice #${invoice.invoice_number}`);
        doc.fontSize(12).text(`Date: ${new Date(invoice.invoice_date).toLocaleDateString()}`);
        doc.text(`Guest: ${invoice.guest_name}`);
        doc.text(`Room: ${invoice.room_number || 'N/A'}`);
        doc.text(`Payment Status: ${invoice.payment_status}`);
        doc.text(`Payment Method: ${invoice.payment_method}`);
        doc.moveDown();
        
        // Invoice items table
        doc.fontSize(12).text('Invoice Items:', { underline: true });
        let yPos = doc.y + 10;
        
        // Table headers
        doc.text('Item', 50, yPos);
        doc.text('Qty', 250, yPos);
        doc.text('Rate', 300, yPos);
        doc.text('GST', 350, yPos);
        doc.text('Total', 450, yPos);
        yPos += 20;
        
        // Table rows
        invoice.items.forEach(item => {
          // Check if we need a new page for this item
          if (yPos > doc.page.height - 100) {
            doc.addPage();
            yPos = 50;
            
            // Reprint headers on new page
            doc.text('Item', 50, yPos);
            doc.text('Qty', 250, yPos);
            doc.text('Rate', 300, yPos);
            doc.text('GST', 350, yPos);
            doc.text('Total', 450, yPos);
            yPos += 20;
          }
          
          doc.text(item.item_name, 50, yPos, { width: 180 });
          doc.text(item.quantity.toString(), 250, yPos);
          doc.text(parseFloat(item.rate).toFixed(2), 300, yPos);
          doc.text(parseFloat(item.gst_amount).toFixed(2), 350, yPos);
          doc.text(parseFloat(item.total).toFixed(2), 450, yPos);
          
          yPos += doc.heightOfString(item.item_name, { width: 180 });
          yPos += 10; // Add some padding between rows
        });
        
        // Invoice totals
        yPos += 20;
        doc.text(`Subtotal: ${parseFloat(invoice.subtotal).toFixed(2)}`, 350, yPos);
        yPos += 20;
        doc.text(`Tax: ${parseFloat(invoice.tax_amount).toFixed(2)}`, 350, yPos);
        yPos += 20;
        doc.text(`Total: ${parseFloat(invoice.total_amount).toFixed(2)}`, 350, yPos, { underline: true });
        
        // Add notes if available
        if (invoice.notes) {
          yPos += 40;
          doc.text('Notes:', 50, yPos);
          yPos += 20;
          doc.text(invoice.notes, 50, yPos, { width: 500 });
        }
      });
      
      // Add footer
      doc.fontSize(10).text(`Generated on ${new Date().toLocaleString()}`, { align: 'center' });
      
      // Finalize the PDF
      doc.end();
      
    } catch (error) {
      reject(error);
    }
  });
}



app.post('/api/invoices/aggregated/kitchen/email', async (req, res) => {
  try {
    const { from_date, to_date, guest_name, email_to } = req.query;
    
    // Validate required parameters
    if (!from_date || !to_date) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'Both from_date and to_date are required' 
      });
    }

    if (!email_to) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'Email address is required' 
      });
    }

    // Format dates for query
    const formattedFromDate = new Date(from_date).toISOString().split('T')[0];
    const formattedToDate = new Date(to_date).toISOString().split('T')[0] + ' 23:59:59';

    // Base query parts
    let guestWhereCondition = '';
    
    if (guest_name) {
      guestWhereCondition = 'AND i.guest_name LIKE ?';
    }

    // Get resort invoices
    const invoiceQuery = `
      SELECT 
        i.id, 
        i.invoice_number, 
        i.invoice_date, 
        i.guest_id,
        i.room_number,
        i.guest_name, 
        i.guest_mobile,
        i.subtotal, 
        i.tax_amount, 
        i.total_amount,
        i.payment_status,
        i.payment_method,
        i.notes,
        i.created_at,
        u.username as created_by_username,
        u.full_name as created_by_name
      FROM 
        invoices i
        LEFT JOIN users u ON i.created_by = u.id
      WHERE 
        i.type = 'kitchen'
        AND i.invoice_date BETWEEN ? AND ?
        ${guestWhereCondition}
      ORDER BY 
        i.invoice_date ASC
    `;
    
    // Prepare parameters for the invoice query
    const invoiceParams = guest_name 
      ? [formattedFromDate, formattedToDate, `%${guest_name}%`] 
      : [formattedFromDate, formattedToDate];
    
    const [invoices] = await pool.query(invoiceQuery, invoiceParams);
    
    if (invoices.length === 0) {
      return res.status(404).json({ 
        status: 'error', 
        message: 'No resort invoices found for the given date range and guest name' 
      });
    }
    
    // Get invoice items for all the invoices
    const invoiceIds = invoices.map(inv => inv.id);
    
    const itemsQuery = `
      SELECT 
        ii.id,
        ii.invoice_id, 
        ii.item_id, 
        ii.service_id,
        ii.item_name, 
        ii.quantity, 
        ii.rate, 
        ii.gst_percentage, 
        ii.gst_amount, 
        ii.total,
        ii.booking_date,
        CASE 
          WHEN ii.item_id IS NOT NULL THEN 'menu_item'
          WHEN ii.service_id IS NOT NULL THEN 'service'
          ELSE 'other'
          END as item_type
      FROM 
        invoice_items ii
      WHERE 
        ii.invoice_id IN (?)
      ORDER BY 
        ii.booking_date ASC, ii.invoice_id ASC
    `;
    
    const [items] = await pool.query(itemsQuery, [invoiceIds]);
    
    // Get resort information for the invoice header
    const [resortInfo] = await pool.query('SELECT * FROM settings LIMIT 1');
    
    // Group invoice items by invoice
    const invoiceItemsMap = items.reduce((acc, item) => {
      if (!acc[item.invoice_id]) {
        acc[item.invoice_id] = [];
      }
      acc[item.invoice_id].push(item);
      return acc;
    }, {});
    
    // Attach items to their respective invoices
    invoices.forEach(invoice => {
      invoice.items = invoiceItemsMap[invoice.id] || [];
    });
    
    // Calculate aggregated totals
    const aggregatedData = {
      resort_info: resortInfo[0],
      date_range: {
        from_date: from_date,
        to_date: to_date
      },
      guest_filter: guest_name || 'All Guests',
      invoices: invoices,
      summary: {
        total_invoices: invoices.length,
        total_subtotal: 0,
        total_tax: 0,
        total_amount: 0,
        payment_status_summary: {
          paid: 0,
          pending: 0,
          cancelled: 0
        },
        payment_method_summary: {
          cash: 0,
          card: 0,
          upi: 0,
          other: 0
        }
      }
    };
    
    // Calculate summary totals
    invoices.forEach(invoice => {
      aggregatedData.summary.total_subtotal += parseFloat(invoice.subtotal);
      aggregatedData.summary.total_tax += parseFloat(invoice.tax_amount);
      aggregatedData.summary.total_amount += parseFloat(invoice.total_amount);
      
      // Count by payment status
      if (invoice.payment_status) {
        const status = invoice.payment_status.toLowerCase();
        if (!aggregatedData.summary.payment_status_summary[status]) {
          aggregatedData.summary.payment_status_summary[status] = 0;
        }
        aggregatedData.summary.payment_status_summary[status]++;
      }
      
      // Count by payment method
      if (invoice.payment_method) {
        const method = invoice.payment_method.toLowerCase();
        if (!aggregatedData.summary.payment_method_summary[method]) {
          aggregatedData.summary.payment_method_summary[method] = 0;
        }
        aggregatedData.summary.payment_method_summary[method]++;
      }
    });

    // Generate HTML email content
    const emailContent = generateInvoiceEmailHTML(aggregatedData);
    
    // Generate PDF attachment (assuming you have a PDF generation library)
    const pdfBuffer = await generateInvoicePDF(aggregatedData);
    
    const mailOptions = {
      from: `"${resortInfo[0].resort_name}" <${process.env.EMAIL_USER}>`,
      to: email_to,
      subject: `Resort Invoice Report (${from_date} to ${to_date})`,
      html: emailContent,
      attachments: [
        {
          filename: `invoice_report_${from_date}_to_${to_date}.pdf`,
          content: pdfBuffer,
          contentType: 'application/pdf'
        }
      ]
    };
    
    // Send email
    const info = await transporter.sendMail(mailOptions);
    
    res.json({
      status: 'success',
      message: 'Invoice report has been sent to the specified email',
      email_details: {
        messageId: info.messageId,
        recipient: email_to
      }
    });
    
  } catch (error) {
    console.error('Error sending invoice email:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'Failed to send invoice email', 
      error: error.message 
    });
  }
});





// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
// </boltAction type="file">
