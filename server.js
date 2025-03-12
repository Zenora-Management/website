/**
 * server.js
 *
 * This Node.js server uses Express and Nodemailer to handle form submissions and
 * send emails via Mailjet. Run with: `node server.js`
 *
 * IMPORTANT:
 * - Do not expose your API keys in public repositories.
 * - For production, store your credentials in environment variables.
 */

const express = require('express');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const connectDB = require('./config/database');
const User = require('./models/User');
const Property = require('./models/Property');
const Message = require('./models/Message');
const Document = require('./models/Document');
const upload = require('./config/upload');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// List of allowed admin emails - RESTRICTED ACCESS
const ALLOWED_ADMIN_EMAILS = process.env.ADMIN_EMAILS ? process.env.ADMIN_EMAILS.split(',') : [
    'anshparikh@gmail.com',
    'anvisrini@gmail.com',
    'zenoramgmt@gmail.com'
];

// Connect to MongoDB
connectDB();

// Create initial admin users if they don't exist (only for first-time setup)
async function createAdminUsersIfNotExist() {
    try {
        const defaultAdminPassword = 'Zenora101!';
        const hashedPassword = await bcrypt.hash(defaultAdminPassword, 10);

        // Create admin users for each allowed email if they don't exist
        for (const email of ALLOWED_ADMIN_EMAILS) {
            const adminExists = await User.findOne({ email });
            
            if (!adminExists) {
                const adminUser = new User({
                    name: 'Admin',
                    email: email,
                    password: hashedPassword,
                    role: 'admin',
                    verified: true
                });
                await adminUser.save();
                console.log(`Admin user created successfully for ${email}`);
            }
        }
    } catch (error) {
        console.error('Error creating admin users:', error);
    }
}

// Call this function only once during initial setup
// createAdminUsersIfNotExist();

// Middleware
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Serve static files from the "public" folder
app.use(express.static('public'));

// Add redirect for admin-dashboard.html
app.get('/portal/admin-dashboard.html', (req, res) => {
    res.redirect('/portal/admin/dashboard.html');
});

/**
 * TRANSPORTER CONFIGURATION - Using Gmail SMTP
 * For this to work:
 * 1. Enable 2-Step Verification in your Gmail account
 * 2. Generate an App Password: Gmail Settings -> Security -> App Passwords
 * 3. Use that App Password here
 */
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Verify the transporter configuration
transporter.verify(function(error, success) {
    if (error) {
        console.error('Error verifying email configuration:', error);
        console.log('Please make sure you have:');
        console.log('1. Enabled 2-Step Verification in your Gmail account');
        console.log('2. Generated an App Password from Gmail Settings');
        console.log('3. Added the correct EMAIL_USER and EMAIL_PASS in your .env file');
    } else {
        console.log('Email server is ready to send messages');
    }
});

// Mock database
const users = [
  { 
    id: 1,
    email: 'demo@example.com', 
    password: 'password', // In production, this would be hashed
    name: 'Demo User',
    role: 'user',
    verified: true,
    createdAt: new Date(),
    properties: [],
    documents: []
  },
  { 
    id: 2,
    email: 'admin@zenora.com', 
    password: 'admin123', // In production, this would be hashed
    name: 'Admin User',
    role: 'admin',
    verified: true,
    createdAt: new Date(),
    properties: [],
    documents: []
  }
];

// Store verification tokens
const verificationTokens = new Map();

// Store password reset tokens with expiration
const passwordResetTokens = new Map();

// Generate verification token
function generateVerificationToken() {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

// Generate a secure random token
function generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

// Send verification email
async function sendVerificationEmail(email, token) {
    const verificationLink = `http://localhost:3000/verify?token=${token}`;
    
    const mailOptions = {
        from: '"Zenora MGMT" <zenoramgmt@gmail.com>',
        to: email,
        subject: 'Verify Your Email - Zenora MGMT',
        html: `
            <h2>Welcome to Zenora MGMT!</h2>
            <p>Please verify your email address by clicking the link below:</p>
            <p><a href="${verificationLink}">Verify Email Address</a></p>
            <p>This link will expire in 24 hours.</p>
            <p>If you did not create an account, please ignore this email.</p>
            <br>
            <p>Best regards,<br>Zenora MGMT Team</p>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log('Verification email sent successfully');
    } catch (error) {
        console.error('Error sending verification email:', error);
        throw error;
    }
}

// Send password reset email
async function sendPasswordResetEmail(email, code) {
    const mailOptions = {
        from: '"Zenora MGMT" <zenoramgmt@gmail.com>',
        to: email,
        subject: 'Password Reset - Zenora MGMT',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #805AD5; margin-bottom: 20px;">Password Reset Request</h2>
                <p>You have requested to reset your password. Use the following verification code to complete the process:</p>
                <div style="background: #f0f0f0; padding: 15px; text-align: center; margin: 20px 0; border-radius: 5px;">
                    <h3 style="font-size: 24px; letter-spacing: 5px; margin: 0; color: #4A5568;">${code}</h3>
                </div>
                <p>This code will expire in 15 minutes.</p>
                <p style="color: #718096; font-size: 14px;">If you did not request this password reset, please ignore this email and ensure your account is secure.</p>
                <hr style="border: none; border-top: 1px solid #E2E8F0; margin: 20px 0;">
                <p style="color: #718096; font-size: 14px;">Best regards,<br>Zenora MGMT Team</p>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log('Password reset email sent successfully');
    } catch (error) {
        console.error('Error sending password reset email:', error);
        throw error;
    }
}

// Verification endpoint
app.get('/verify', async (req, res) => {
    try {
        const { token } = req.query;
        
        if (!token) {
            return res.status(400).send('Verification token is required');
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (!user) {
            return res.status(404).send('User not found');
        }

        if (user.verified) {
            return res.redirect('/auth/login.html?alreadyVerified=true');
        }

        user.verified = true;
        user.verificationToken = undefined;
        await user.save();

        res.redirect('/auth/login.html?verified=true');
    } catch (error) {
        console.error('Error verifying email:', error);
        res.status(400).send('Invalid or expired verification token');
    }
});

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ success: false, message: 'No token provided' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id);
        
        if (!user) {
            return res.status(403).json({ success: false, message: 'User not found' });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(403).json({ success: false, message: 'Invalid token' });
    }
};

// Admin middleware
const requireAdmin = async (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'Admin access required' });
    }
    next();
};

// User profile endpoint
app.get('/api/user/profile', authenticateToken, (req, res) => {
  const user = users.find(u => u.email === req.user.email);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }
  
  res.json({
    success: true,
    user: {
      name: user.name,
      email: user.email,
      role: user.role
    }
  });
});

// User dashboard endpoint
app.get('/api/user/dashboard', authenticateToken, async (req, res) => {
    try {
        // Find user with populated properties
        const user = await User.findById(req.user._id).populate('properties');
        
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        // Check if user has no properties
        if (!user.properties || user.properties.length === 0) {
            return res.json({
                success: true,
                hasProperties: false,
                message: 'You have no properties yet.',
                listPropertyUrl: '/list-your-home.html'
            });
        }
        
        // If user has properties, return dashboard data
        const dashboardData = {
            hasProperties: true,
            properties: {
                total: user.properties.length,
                activeTenants: user.properties.filter(p => p.tenant).length,
                maintenanceRequests: user.properties.reduce((acc, p) => acc + (p.maintenanceRequests ? p.maintenanceRequests.length : 0), 0)
            },
            financial: {
                monthlyRevenue: user.properties.reduce((acc, p) => acc + (p.rent || 0), 0),
                nextPaymentDue: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toLocaleDateString(),
                outstandingBalance: 0
            },
            recentUpdates: [
                {
                    title: 'Welcome to Your Dashboard',
                    description: 'Start managing your properties efficiently with Zenora MGMT.',
                    date: new Date().toLocaleDateString()
                }
            ]
        };

        res.json({
            success: true,
            ...dashboardData
        });
    } catch (error) {
        console.error('Error fetching dashboard data:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching dashboard data'
        });
    }
});

// Admin Routes
app.get('/api/admin/profile', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const admin = await User.findById(req.user._id).select('-password');
        res.json({ success: true, user: admin });
    } catch (error) {
        console.error('Error fetching admin profile:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/api/admin/dashboard', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments({ role: 'user' });
        const totalProperties = await Property.countDocuments();
        const totalDocuments = await Document.countDocuments();

        const recentActivity = await Promise.all([
            User.find().sort({ createdAt: -1 }).limit(5),
            Property.find().sort({ createdAt: -1 }).limit(5),
            Document.find().sort({ uploadedAt: -1 }).limit(5)
        ]);

        const [recentUsers, recentProperties, recentDocs] = recentActivity;

        const activity = [
            ...recentUsers.map(user => ({
                type: 'user',
                description: `New user registered: ${user.name}`,
                timestamp: user.createdAt
            })),
            ...recentProperties.map(prop => ({
                type: 'property',
                description: `Property added: ${prop.address}`,
                timestamp: prop.createdAt
            })),
            ...recentDocs.map(doc => ({
                type: 'document',
                description: `Document uploaded: ${doc.title}`,
                timestamp: doc.uploadedAt
            }))
        ].sort((a, b) => b.timestamp - a.timestamp).slice(0, 10);

        res.json({
            success: true,
            totalUsers,
            totalProperties,
            totalDocuments,
            recentActivity: activity
        });
    } catch (error) {
        console.error('Error in admin dashboard:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find({ role: 'user' })
            .select('-password')
            .populate('properties documents');

        const usersList = users.map(user => ({
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            verified: user.verified,
            propertiesCount: user.properties.length,
            documentsCount: user.documents.length,
            createdAt: user.createdAt
        }));

        res.json({ success: true, users: usersList });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.put('/api/admin/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const { name, email, role, verified } = req.body;

        const user = await User.findByIdAndUpdate(
            userId,
            { name, email, role, verified },
            { new: true }
        ).select('-password');

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        res.json({ success: true, user });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.delete('/api/admin/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await User.findByIdAndDelete(userId);
        
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Delete associated properties and documents
        await Property.deleteMany({ owner: userId });
        await Document.deleteMany({ owner: userId });

        res.json({ success: true, message: 'User and associated data deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Get user properties
app.get('/api/user/properties', authenticateToken, (req, res) => {
  const user = users.find(u => u.email === req.user.email);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  res.json({
    success: true,
    properties: user.properties
  });
});

// Get user documents
app.get('/api/user/documents', authenticateToken, (req, res) => {
  const user = users.find(u => u.email === req.user.email);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  res.json({
    success: true,
    documents: user.documents
  });
});

// Add a property
app.post('/api/user/properties', authenticateToken, (req, res) => {
  const user = users.find(u => u.email === req.user.email);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  const newProperty = {
    id: Date.now(),
    ...req.body,
    maintenanceRequests: [],
    documents: [],
    createdAt: new Date()
  };

  user.properties.push(newProperty);

  res.json({
    success: true,
    property: newProperty
  });
});

// Add a document
app.post('/api/user/documents', authenticateToken, (req, res) => {
  const user = users.find(u => u.email === req.user.email);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  const newDocument = {
    id: Date.now(),
    ...req.body,
    uploadedAt: new Date()
  };

  user.documents.push(newDocument);

  res.json({
    success: true,
    document: newDocument
  });
});

//--------------------- CONTACT FORM ENDPOINT ---------------------
app.post('/sendContactEmail', async (req, res) => {
  try {
    const { name, email, phone, message } = req.body;

    const mailOptions = {
      from: `"Zenora MGMT Website" <anvisrini@gmail.com>`,
      to: 'zenoramgmt@gmail.com',
      subject: 'New Contact Form Submission',
      text: `
New contact form submission:

Name: ${name}
Email: ${email}
Phone: ${phone}
Message: ${message}
      `
    };

    await transporter.sendMail(mailOptions);
    return res.json({ success: true, message: 'Your message was sent successfully!' });
  } catch (error) {
    console.error('Error sending contact email:', error);
    return res.status(500).json({ success: false, message: 'Something went wrong sending the email.' });
  }
});

//----------------- "LIST YOUR HOME" FORM ENDPOINT ----------------
app.post('/sendListingEmail', async (req, res) => {
  try {
    const {
      plan,
      firstName,
      lastName,
      email,
      phone,
      bedrooms,
      bathrooms,
      sqft,
      address,
      referral,
      description
    } = req.body;

    const mailOptions = {
      from: `"Zenora MGMT Website" <anvisrini@gmail.com>`,
      to: 'zenoramgmt@gmail.com',
      subject: 'New Listing Form Submission',
      text: `
New home listing submitted:

Plan Interested: ${plan}
First Name: ${firstName}
Last Name: ${lastName}
Email: ${email}
Phone: ${phone}
Bedrooms: ${bedrooms}
Bathrooms: ${bathrooms}
Square Footage: ${sqft}
Address: ${address}
Referral/Prev. Management: ${referral}
Additional Info: ${description}
      `
    };

    await transporter.sendMail(mailOptions);
    return res.json({ success: true, message: 'Listing submitted successfully!' });
  } catch (error) {
    console.error('Error sending listing email:', error);
    return res.status(500).json({ success: false, message: 'Something went wrong sending the listing email.' });
  }
});

//--------- RENT ANALYSIS FORM ENDPOINT (OPTIONAL) ---------
app.post('/sendRentAnalysisEmail', async (req, res) => {
  try {
    const { address, bedrooms, bathrooms, preferredTime } = req.body;

    const mailOptions = {
      from: `"Zenora MGMT Website" <anvisrini@gmail.com>`,
      to: 'zenoramgmt@gmail.com',
      subject: 'New Rent Analysis Request',
      text: `
New rent analysis request:

Address: ${address}
Bedrooms: ${bedrooms}
Bathrooms: ${bathrooms}
Preferred Call Time: ${preferredTime}
      `
    };

    await transporter.sendMail(mailOptions);
    return res.json({ success: true, message: 'Rent analysis request sent!' });
  } catch (error) {
    console.error('Error sending rent analysis email:', error);
    return res.status(500).json({ success: false, message: 'Error sending rent analysis email.' });
  }
});

// Rate limiting for login attempts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: {
        success: false,
        message: 'Too many login attempts. Please try again after 15 minutes.'
    }
});

// Password validation function
function validatePassword(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    const errors = [];
    if (password.length < minLength) errors.push('be at least 8 characters long');
    if (!hasUpperCase) errors.push('contain at least one uppercase letter');
    if (!hasLowerCase) errors.push('contain at least one lowercase letter');
    if (!hasNumbers) errors.push('contain at least one number');
    if (!hasSpecialChar) errors.push('contain at least one special character');

    return {
        isValid: errors.length === 0,
        errors: errors
    };
}

// Apply rate limiting to login routes
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Login attempt:', { email });

        const user = await User.findOne({ email });
        console.log('User found:', user ? 'Yes' : 'No');

        // Regular user login only
        if (!user || user.role === 'admin') {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        console.log('Password valid:', isValidPassword);

        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        const token = jwt.sign({
            id: user._id,
            email: user.email,
            name: user.name,
            role: user.role
        }, JWT_SECRET);

        console.log('Login successful for:', user.email);

        res.json({
            success: true,
            token,
            user: {
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Error in login:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error: ' + error.message
        });
    }
});

// Separate admin login endpoint
app.post('/api/auth/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Admin login attempt:', { email });

        if (!email || !ALLOWED_ADMIN_EMAILS.includes(email)) {
            return res.status(401).json({
                success: false,
                message: 'Invalid admin credentials'
            });
        }

        let user = await User.findOne({ email });

        // Verify admin password
        if (password !== 'Zenora101!') {
            console.log('Invalid admin password attempt');
            return res.status(401).json({
                success: false,
                message: 'Invalid admin credentials'
            });
        }

        if (!user) {
            // Create admin user if it doesn't exist
            const hashedPassword = await bcrypt.hash('Zenora101!', 10);
            const newAdmin = new User({
                name: 'Admin',
                email: email,
                password: hashedPassword,
                role: 'admin',
                verified: true
            });
            user = await newAdmin.save();
        }

        const token = jwt.sign({
            id: user._id,
            email: user.email,
            name: user.name,
            role: 'admin'
        }, JWT_SECRET);

        return res.json({
            success: true,
            token,
            user: {
                name: user.name,
                email: user.email,
                role: 'admin'
            }
        });
    } catch (error) {
        console.error('Error in admin login:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error: ' + error.message
        });
    }
});

app.post('/api/auth/register', async (req, res) => {
    try {
        const { 
            name, 
            email, 
            password,
            propertyAddress,
            propertyType,
            bedrooms,
            bathrooms,
            sqft,
            rent
        } = req.body;
        console.log('Registration attempt:', { name, email, propertyAddress });

        // Validate password
        const passwordValidation = validatePassword(password);
        if (!passwordValidation.isValid) {
            return res.status(400).json({
                success: false,
                message: `Password must ${passwordValidation.errors.join(', ')}`
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                message: 'Please enter a valid email address'
            });
        }

        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'There is already an account associated with this email. Please use a different email or login to your existing account.'
            });
        }

        // Create user
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            name,
            email,
            password: hashedPassword,
            role: 'user',
            verified: true
        });

        await user.save();
        console.log('User created successfully:', user._id);

        // Create property
        const property = new Property({
            address: propertyAddress,
            type: propertyType || 'House', // Default to House if not specified
            owner: user._id,
            bedrooms: bedrooms || 0,
            bathrooms: bathrooms || 0,
            sqft: sqft || 0,
            rent: rent || 0,
            status: 'Active'
        });

        await property.save();
        console.log('Property created successfully:', property._id);

        // Add property reference to user
        user.properties = [property._id];
        await user.save();

        // Generate JWT token for immediate login
        const token = jwt.sign({
            id: user._id,
            email: user.email,
            name: user.name,
            role: user.role
        }, JWT_SECRET);

        res.json({
            success: true,
            message: 'Registration successful.',
            token,
            user: {
                name: user.name,
                email: user.email,
                role: user.role,
                property: {
                    address: property.address,
                    type: property.type
                }
            }
        });
    } catch (error) {
        console.error('Error in registration:', error);
        res.status(500).json({
            success: false,
            message: 'Error during registration: ' + error.message
        });
    }
});

// Properties Routes
app.get('/api/admin/properties', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const properties = await Property.find()
            .populate('owner', 'name email')
            .populate('documents');

        res.json({ success: true, properties });
    } catch (error) {
        console.error('Error fetching properties:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/admin/properties', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId, ...propertyData } = req.body;
        const user = await User.findById(userId);
        
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const property = new Property({
            ...propertyData,
            owner: userId
        });

        await property.save();
        user.properties.push(property._id);
        await user.save();

        res.json({ success: true, property });
    } catch (error) {
        console.error('Error adding property:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.put('/api/admin/properties/:propertyId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { propertyId } = req.params;
        const property = await Property.findByIdAndUpdate(
            propertyId,
            req.body,
            { new: true }
        ).populate('owner', 'name email');

        if (!property) {
            return res.status(404).json({ success: false, message: 'Property not found' });
        }

        res.json({ success: true, property });
    } catch (error) {
        console.error('Error updating property:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.delete('/api/admin/properties/:propertyId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { propertyId } = req.params;
        const property = await Property.findById(propertyId);
        
        if (!property) {
            return res.status(404).json({ success: false, message: 'Property not found' });
        }

        // Remove property reference from owner
        await User.findByIdAndUpdate(property.owner, {
            $pull: { properties: propertyId }
        });

        // Delete associated documents
        await Document.deleteMany({ property: propertyId });
        await property.remove();

        res.json({ success: true, message: 'Property deleted successfully' });
    } catch (error) {
        console.error('Error deleting property:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Messages Routes
app.get('/api/admin/messages', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const messages = await Message.find()
            .populate('sender', 'name email')
            .populate('recipient', 'name email')
            .sort({ createdAt: -1 });

        res.json({ success: true, messages });
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/api/admin/messages/:messageId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { messageId } = req.params;
        const message = await Message.findById(messageId)
            .populate('sender', 'name email')
            .populate('recipient', 'name email')
            .populate('replies.sender', 'name email');

        if (!message) {
            return res.status(404).json({ success: false, message: 'Message not found' });
        }

        res.json({ success: true, message });
    } catch (error) {
        console.error('Error fetching message:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/admin/messages/:messageId/reply', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { messageId } = req.params;
        const { content } = req.body;

        const message = await Message.findById(messageId);
        if (!message) {
            return res.status(404).json({ success: false, message: 'Message not found' });
        }

        message.replies.push({
            content,
            sender: req.user._id
        });

        await message.save();
        res.json({ success: true, message: 'Reply sent successfully' });
    } catch (error) {
        console.error('Error sending reply:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/admin/messages/:messageId/archive', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { messageId } = req.params;
        const message = await Message.findByIdAndUpdate(
            messageId,
            { archived: true },
            { new: true }
        );

        if (!message) {
            return res.status(404).json({ success: false, message: 'Message not found' });
        }

        res.json({ success: true, message: 'Message archived successfully' });
    } catch (error) {
        console.error('Error archiving message:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Admin API endpoints
app.get('/api/admin/clients', authenticateToken, async (req, res) => {
    try {
        // Check if user is admin
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized access' });
        }

        // Get all users with role 'user'
        const clients = await User.find({ role: 'user' }).select('-password');
        
        // Get properties for each client
        const clientsWithProperties = await Promise.all(clients.map(async (client) => {
            const properties = await Property.find({ owner: client._id });
            return {
                ...client.toObject(),
                properties
            };
        }));

        res.json({ clients: clientsWithProperties });
    } catch (error) {
        console.error('Error fetching clients:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/admin/properties', authenticateToken, async (req, res) => {
    try {
        // Check if user is admin
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized access' });
        }

        // Get all properties with populated owner and documents
        const properties = await Property.find()
            .populate('owner', '-password')
            .populate('documents');

        res.json({ properties });
    } catch (error) {
        console.error('Error fetching properties:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/properties/:propertyId/documents', authenticateToken, upload.single('document'), async (req, res) => {
    try {
        // Check if user is admin
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized access' });
        }

        const { propertyId } = req.params;
        const { name, description } = req.body;

        // Check if property exists
        const property = await Property.findById(propertyId);
        if (!property) {
            return res.status(404).json({ error: 'Property not found' });
        }

        // Create new document
        const document = new Document({
            name,
            description,
            file: req.file.filename,
            property: propertyId,
            uploadedBy: req.user._id
        });

        await document.save();

        // Add document to property
        property.documents.push(document._id);
        await property.save();

        res.json({ document });
    } catch (error) {
        console.error('Error uploading document:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/admin/properties/:propertyId/documents', authenticateToken, async (req, res) => {
    try {
        // Check if user is admin
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized access' });
        }

        const { propertyId } = req.params;

        // Get all documents for the property
        const documents = await Document.find({ property: propertyId })
            .populate('uploadedBy', '-password');

        res.json({ documents });
    } catch (error) {
        console.error('Error fetching documents:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/admin/properties/:propertyId', authenticateToken, async (req, res) => {
    try {
        // Check if user is admin
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized access' });
        }

        const { propertyId } = req.params;
        const updateData = req.body;

        // Update property
        const property = await Property.findByIdAndUpdate(
            propertyId,
            updateData,
            { new: true }
        ).populate('owner', '-password');

        if (!property) {
            return res.status(404).json({ error: 'Property not found' });
        }

        res.json({ property });
    } catch (error) {
        console.error('Error updating property:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/admin/properties/:propertyId', authenticateToken, async (req, res) => {
    try {
        // Check if user is admin
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized access' });
        }

        const { propertyId } = req.params;

        // Delete all documents associated with the property
        await Document.deleteMany({ property: propertyId });

        // Delete the property
        const property = await Property.findByIdAndDelete(propertyId);

        if (!property) {
            return res.status(404).json({ error: 'Property not found' });
        }

        res.json({ message: 'Property deleted successfully' });
    } catch (error) {
        console.error('Error deleting property:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Forgot password endpoint
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        console.log('Forgot password request received for:', email);

        // Find user
        const user = await User.findOne({ email });
        
        // For security, we'll send the same response regardless of whether the user exists
        const standardResponse = {
            success: true,
            message: 'If an account exists with this email, a password reset code will be sent.'
        };

        if (!user) {
            console.log('No user found with email:', email);
            return res.json(standardResponse);
        }

        // Generate a 6-digit verification code
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        console.log('Generated verification code');
        
        // Store the code with expiration (15 minutes)
        passwordResetTokens.set(email, {
            code: verificationCode,
            expiry: Date.now() + 15 * 60 * 1000, // 15 minutes
            userId: user._id
        });

        // Send reset email
        try {
            await sendPasswordResetEmail(email, verificationCode);
            console.log('Password reset email sent successfully');
            return res.json(standardResponse);
        } catch (emailError) {
            console.error('Error sending password reset email:', emailError);
            // Remove the stored token if email fails
            passwordResetTokens.delete(email);
            return res.status(500).json({
                success: false,
                message: 'Failed to send password reset email. Please try again later.'
            });
        }
    } catch (error) {
        console.error('Error in forgot password:', error);
        return res.status(500).json({
            success: false,
            message: 'An error occurred while processing your request. Please try again later.'
        });
    }
});

// Reset password endpoint
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { code, newPassword } = req.body;

        // Find the email associated with this code
        let userEmail = null;
        let userId = null;

        for (const [email, data] of passwordResetTokens.entries()) {
            if (data.code === code) {
                // Check if code has expired
                if (Date.now() > data.expiry) {
                    passwordResetTokens.delete(email);
                    return res.status(400).json({
                        success: false,
                        message: 'Verification code has expired. Please request a new one.'
                    });
                }
                userEmail = email;
                userId = data.userId;
                break;
            }
        }

        if (!userEmail) {
            return res.status(400).json({
                success: false,
                message: 'Invalid verification code'
            });
        }

        // Validate password
        const passwordValidation = validatePassword(newPassword);
        if (!passwordValidation.isValid) {
            return res.status(400).json({
                success: false,
                message: `Password must ${passwordValidation.errors.join(', ')}`
            });
        }

        // Update user's password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await User.findByIdAndUpdate(userId, { password: hashedPassword });

        // Remove the used token
        passwordResetTokens.delete(userEmail);

        res.json({
            success: true,
            message: 'Password has been reset successfully'
        });
    } catch (error) {
        console.error('Error in reset password:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred while resetting your password'
        });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});