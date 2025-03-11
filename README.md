# Zenora MGMT Website

A property management platform built with Node.js, Express, and MongoDB.

## Features

- User Authentication (Regular users and Admins)
- Property Management
- Document Management
- Contact Forms
- Email Notifications
- Password Reset Functionality
- Admin Dashboard
- User Dashboard

## Prerequisites

- Node.js (v14 or higher)
- MongoDB
- Gmail account for email notifications

## Installation

1. Clone the repository:
```bash
git clone <your-repository-url>
cd website
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file in the root directory and add your environment variables:
```env
JWT_SECRET=your-secret-key
MONGODB_URI=your-mongodb-uri
GMAIL_USER=your-gmail
GMAIL_APP_PASSWORD=your-app-password
```

4. Start the server:
```bash
node server.js
```

The server will start on port 3000 by default.

## API Endpoints

### Authentication
- POST `/api/auth/login` - User login
- POST `/api/auth/admin/login` - Admin login
- POST `/api/auth/register` - User registration
- POST `/api/auth/forgot-password` - Request password reset
- POST `/api/auth/reset-password` - Reset password

### User Routes
- GET `/api/user/profile` - Get user profile
- GET `/api/user/dashboard` - Get user dashboard
- GET `/api/user/properties` - Get user properties
- GET `/api/user/documents` - Get user documents
- POST `/api/user/properties` - Add a property
- POST `/api/user/documents` - Add a document

### Admin Routes
- GET `/api/admin/profile` - Get admin profile
- GET `/api/admin/dashboard` - Get admin dashboard
- GET `/api/admin/users` - Get all users
- GET `/api/admin/properties` - Get all properties
- GET `/api/admin/messages` - Get all messages

## Security Features

- Password hashing with bcrypt
- JWT authentication
- Rate limiting for login attempts
- Secure password reset flow
- Input validation
- XSS protection
- CORS enabled
- Secure email configuration

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 