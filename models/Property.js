const mongoose = require('mongoose');

const propertySchema = new mongoose.Schema({
    address: {
        type: String,
        required: true,
        trim: true
    },
    type: {
        type: String,
        required: true,
        enum: ['House', 'Apartment', 'Condo', 'Townhouse', 'Other']
    },
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    status: {
        type: String,
        enum: ['Active', 'Pending', 'Inactive'],
        default: 'Active'
    },
    tenant: {
        name: String,
        email: String,
        phone: String,
        leaseStart: Date,
        leaseEnd: Date
    },
    rent: {
        type: Number,
        required: true
    },
    bedrooms: {
        type: Number,
        required: true
    },
    bathrooms: {
        type: Number,
        required: true
    },
    sqft: {
        type: Number,
        required: true
    },
    maintenanceRequests: [{
        title: String,
        description: String,
        status: {
            type: String,
            enum: ['pending', 'in-progress', 'completed'],
            default: 'pending'
        },
        createdAt: {
            type: Date,
            default: Date.now
        }
    }],
    documents: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Document'
    }],
    image: {
        type: String,
        default: null
    },
    details: {
        bedrooms: {
            type: Number,
            default: 0
        },
        bathrooms: {
            type: Number,
            default: 0
        },
        squareFeet: {
            type: Number,
            default: 0
        }
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Update the updatedAt timestamp before saving
propertySchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

// Add method to check if user has access to property
propertySchema.methods.canAccess = function(userId) {
    return this.owner.equals(userId);
};

const Property = mongoose.model('Property', propertySchema);

module.exports = Property; 