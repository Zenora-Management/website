const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('./models/User');

async function createAdminUser() {
    try {
        // Connect to MongoDB
        await mongoose.connect('mongodb://localhost:27017/zenora', {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });

        // Check if admin already exists
        const existingAdmin = await User.findOne({ email: 'admin@zenora.com' });
        if (existingAdmin) {
            console.log('Admin user already exists');
            process.exit(0);
        }

        // Create admin user
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
    } catch (error) {
        console.error('Error creating admin user:', error);
    } finally {
        await mongoose.connection.close();
    }
}

createAdminUser(); 