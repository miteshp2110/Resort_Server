-- Database initialization script

-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS resort_kitchen_management;
USE resort_kitchen_management;

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  full_name VARCHAR(100) NOT NULL,
  email VARCHAR(100) UNIQUE,
  role ENUM('admin', 'reception', 'kitchen', 'staff') NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Settings table
CREATE TABLE IF NOT EXISTS settings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  resort_name VARCHAR(100) NOT NULL,
  resort_gstin VARCHAR(20) NOT NULL,
  kitchen_gstin VARCHAR(20) NOT NULL,
  resort_address TEXT NOT NULL,
  resort_contact VARCHAR(100) NOT NULL,
  resort_email VARCHAR(100),
  tax_rate DECIMAL(5,2) DEFAULT 18.00,
  logo_path VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Menu items table
CREATE TABLE IF NOT EXISTS menu_items (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  price DECIMAL(10,2) NOT NULL,
  gst_percentage DECIMAL(5,2) NOT NULL DEFAULT 18.00,
  type ENUM('kitchen', 'resort') NOT NULL,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Services table
CREATE TABLE IF NOT EXISTS services (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  price DECIMAL(10,2) NOT NULL,
  gst_percentage DECIMAL(5,2) NOT NULL DEFAULT 18.00,
  type ENUM('resort') NOT NULL DEFAULT 'resort',
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Guests table
CREATE TABLE IF NOT EXISTS guests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  mobile VARCHAR(20),
  email VARCHAR(100),
  room_number VARCHAR(20),
  check_in_date TIMESTAMP,
  check_out_date TIMESTAMP,
  is_checked_out BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Invoices table
CREATE TABLE IF NOT EXISTS invoices (
  id INT AUTO_INCREMENT PRIMARY KEY,
  invoice_number VARCHAR(50) NOT NULL UNIQUE,
  invoice_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  guest_id INT,
  room_number VARCHAR(20),
  guest_name VARCHAR(100) NOT NULL,
  guest_mobile VARCHAR(20),
  type ENUM('resort', 'kitchen') NOT NULL,
  subtotal DECIMAL(10,2) NOT NULL,
  tax_amount DECIMAL(10,2) NOT NULL,
  total_amount DECIMAL(10,2) NOT NULL,
  payment_status ENUM('paid', 'pending', 'cancelled') DEFAULT 'pending',
  payment_method ENUM('cash', 'card', 'upi', 'other') DEFAULT 'cash',
  notes TEXT,
  booking_date DATE,
  created_by INT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (guest_id) REFERENCES guests(id) ON DELETE SET NULL,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Invoice items table
CREATE TABLE IF NOT EXISTS invoice_items (
  id INT AUTO_INCREMENT PRIMARY KEY,
  invoice_id INT NOT NULL,
  item_id INT,
  service_id INT,
  item_name VARCHAR(100) NOT NULL,
  quantity INT NOT NULL,
  rate DECIMAL(10,2) NOT NULL,
  gst_percentage DECIMAL(5,2) NOT NULL,
  gst_amount DECIMAL(10,2) NOT NULL,
  total DECIMAL(10,2) NOT NULL,
  booking_date date,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (invoice_id) REFERENCES invoices(id) ON DELETE CASCADE,
  FOREIGN KEY (item_id) REFERENCES menu_items(id) ON DELETE SET NULL,
  FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE SET NULL
);

-- Kitchen orders table
CREATE TABLE IF NOT EXISTS kitchen_orders (
  id INT AUTO_INCREMENT PRIMARY KEY,
  order_number VARCHAR(50) NOT NULL UNIQUE,
  order_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  guest_id INT,
  room_number VARCHAR(20),
  guest_name VARCHAR(100) NOT NULL,
  order_type ENUM('room', 'walk_in') NOT NULL,
  status ENUM('pending', 'processing', 'completed', 'cancelled') DEFAULT 'pending',
  subtotal DECIMAL(10,2) NOT NULL,
  tax_amount DECIMAL(10,2) NOT NULL,
  total_amount DECIMAL(10,2) NOT NULL,
  invoice_id INT,
  created_by INT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (guest_id) REFERENCES guests(id) ON DELETE SET NULL,
  FOREIGN KEY (invoice_id) REFERENCES invoices(id) ON DELETE SET NULL,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Kitchen order items table
CREATE TABLE IF NOT EXISTS kitchen_order_items (
  id INT AUTO_INCREMENT PRIMARY KEY,
  order_id INT NOT NULL,
  item_id INT NOT NULL,
  quantity INT NOT NULL,
  rate DECIMAL(10,2) NOT NULL,
  gst_percentage DECIMAL(5,2) NOT NULL,
  gst_amount DECIMAL(10,2) NOT NULL,
  total DECIMAL(10,2) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (order_id) REFERENCES kitchen_orders(id) ON DELETE CASCADE,
  FOREIGN KEY (item_id) REFERENCES menu_items(id) ON DELETE CASCADE
);

-- Insert default admin user
INSERT INTO users (username, password, full_name, email, role)
VALUES ('admin', '$2a$10$YKm8QvYOYleXGrBZnNbVZeuK7eolMIKCXMCrOBNQNZj1ry1R9I9JS', 'Admin User', 'admin@example.com', 'admin');
-- Password is 'admin123'

-- Insert default settings
INSERT INTO settings (resort_name, resort_gstin, kitchen_gstin, resort_address, resort_contact, resort_email, tax_rate)
VALUES ('Mountain View Resort & Spa', '29AALFM0202M1ZE', '29AALFM0202M2ZD', '123 Mountain View Road, Shimla, Himachal Pradesh, India', '+91 9876543210', 'info@mountainviewresort.com', 18.00);

-- Insert sample menu items
INSERT INTO menu_items (name, description, price, gst_percentage, type)
VALUES 
('Butter Chicken', 'Classic North Indian dish with tender chicken in a buttery tomato sauce', 450.00, 18.00, 'kitchen'),
('Paneer Tikka', 'Grilled cottage cheese marinated in spices', 350.00, 18.00, 'kitchen'),
('Veg Biryani', 'Fragrant rice dish with mixed vegetables and spices', 300.00, 18.00, 'kitchen'),
('Masala Chai', 'Traditional Indian spiced tea', 80.00, 18.00, 'kitchen'),
('Breakfast Buffet', 'Complete breakfast with Indian and Continental options', 499.00, 18.00, 'resort'),
('Spa Massage - 60 min', '60-minute relaxing full body massage', 2500.00, 18.00, 'resort');

-- Insert sample services
INSERT INTO services (name, description, price, gst_percentage)
VALUES 
('Conference Hall - Half Day', 'Conference hall rental for half day (4 hours)', 15000.00, 18.00),
('Conference Hall - Full Day', 'Conference hall rental for full day (8 hours)', 25000.00, 18.00),
('Extra Bed', 'Additional bed in room', 1000.00, 18.00),
('Laundry Service', 'Per garment laundry service', 200.00, 18.00),
('Airport Transfer', 'One-way airport transfer', 1500.00, 18.00);