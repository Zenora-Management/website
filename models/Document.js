const mongoose = require('mongoose');

const documentSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true
    },
    type: {
        type: String,
        required: true,
        enum: ['lease', 'maintenance', 'invoice', 'contract', 'other']
    },
    fileUrl: {
        type: String,
        required: true
    },
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    property: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Property'
    },
    description: {
        type: String,
        trim: true
    },
    tags: [{
        type: String,
        trim: true
    }],
    uploadedAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Document', documentSchema); 