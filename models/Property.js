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
        enum: ['House', 'Apartment', 'Condo', 'Townhouse']
    },
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
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
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Property', propertySchema); 