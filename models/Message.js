const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    subject: {
        type: String,
        required: true,
        trim: true
    },
    content: {
        type: String,
        required: true
    },
    sender: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    recipient: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    read: {
        type: Boolean,
        default: false
    },
    archived: {
        type: Boolean,
        default: false
    },
    replies: [{
        content: String,
        sender: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        createdAt: {
            type: Date,
            default: Date.now
        }
    }],
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Message', messageSchema); 