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

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Connect to MongoDB
connectDB();

// Create admin user if doesn't exist
async function createAdminIfNotExists() {
    try {
        const adminExists = await User.findOne({ email: 'admin@zenora.com' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            const adminUser = new User({
                name: 'Admin User',
                email: 'admin@zenora.com',
                password: hashedPassword,
                role: 'admin',
                verified: true
            });
            await adminUser.save();
            console.log('Admin user created successfully');
        }
    } catch (error) {
        console.error('Error checking/creating admin:', error);
    }
}

createAdminIfNotExists();

// Middleware
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Serve static files from the "public" folder
app.use(express.static('public'));

/**
 * TRANSPORTER CONFIGURATION - Using Gmail SMTP
 *
 * SMTP details for Gmail:
 *   - Service: 'gmail'
 *   - Authentication: Your Gmail address and Gmail App Password.
 *
 * The credentials below are as provided. For production, use environment variables.
 */
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'zenoramgmt@gmail.com', // Your Gmail address
        pass: 'kqtc qwxp rnvs yvzm'  // Your Gmail App Password
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

// Generate verification token
function generateVerificationToken() {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
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
app.get('/api/user/dashboard', authenticateToken, (req, res) => {
  const user = users.find(u => u.email === req.user.email);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }
  
  // Mock dashboard data - in production, this would come from a database
  const dashboardData = {
    properties: {
      total: user.properties.length,
      activeTenants: user.properties.filter(p => p.tenant).length,
      maintenanceRequests: user.properties.reduce((acc, p) => acc + p.maintenanceRequests.length, 0)
    },
    financial: {
      monthlyRevenue: user.properties.reduce((acc, p) => acc + (p.rent || 0), 0),
      nextPaymentDue: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toLocaleDateString(),
      outstandingBalance: 0
    },
    recentUpdates: [
      {
        title: 'Maintenance Request Completed',
        description: 'HVAC system maintenance has been completed at 123 Main St.',
        date: new Date().toLocaleDateString()
      },
      {
        title: 'Rent Payment Received',
        description: 'March rent payment received from tenant at 456 Oak Ave.',
        date: new Date(Date.now() - 24 * 60 * 60 * 1000).toLocaleDateString()
      }
    ]
  };

  res.json({
    success: true,
    ...dashboardData
  });
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

// Authentication endpoints
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Login attempt:', { email }); // Log login attempt

        const user = await User.findOne({ email });
        console.log('User found:', user ? 'Yes' : 'No'); // Log if user was found

        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        console.log('Password valid:', isValidPassword); // Log password validation

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

        console.log('Login successful for:', user.email); // Log successful login

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

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        console.log('Registration attempt:', { name, email }); // Log registration attempt

        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Name, email, and password are required'
            });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'Email already registered'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            name,
            email,
            password: hashedPassword,
            verified: true // Temporarily set to true for testing
        });

        await user.save();
        console.log('User created successfully:', user._id); // Log successful creation

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
                role: user.role
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

// Start the server
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});