const mongoose = require('mongoose');

const documentSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    description: {
        type: String,
        default: ''
    },
    file: {
        type: String,
        required: true
    },
    property: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Property',
        required: true
    },
    uploadedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    uploadedAt: {
        type: Date,
        default: Date.now
    },
    status: {
        type: String,
        enum: ['active', 'archived'],
        default: 'active'
    }
});

// Add virtual for file URL
documentSchema.virtual('fileUrl').get(function() {
    return `/uploads/${this.file}`;
});

// Add method to check if user has access to document
documentSchema.methods.canAccess = async function(userId) {
    try {
        // Populate property and its owner if not already populated
        const populatedDoc = await this.populate('property');
        const property = await populatedDoc.property.populate('owner');
        
        // User can access if they are the owner of the property or if they uploaded the document
        return property.owner._id.equals(userId) || this.uploadedBy.equals(userId);
    } catch (error) {
        console.error('Error checking document access:', error);
        return false;
    }
};

const Document = mongoose.model('Document', documentSchema);

module.exports = Document; 