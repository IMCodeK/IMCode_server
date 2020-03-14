const mongoose = require('mongoose');

const {
    Schema
} = mongoose;
const {
    Types: {
        ObjectId
    }
} = Schema;

const videoSchema = new Schema({
    id: {
        type: String,
        required: true,
    },
    channel: {
        type: ObjectId,
        required: true,
        ref: 'Channel',
    },
    video_name: {
        type: String,
        required: false,
    },
    description: {
        type: String,
        required: false,
    },
    img: {
        type: String,
        required: true,
    },
    viewCount: {
        type: Number,
        required: false,
    },
    likeCount: {
        type: Number,
        required: false,
    },
    dislikeCount: {
        type: Number,
        required: false,
    },
    commentCount: {
        type: Number,
        required: false,
    },
    length: {
        type: String,
        required: false,
    },
    category: {
        type: Number,
        required: false,
    },
    publishedAt: {
        type: Date,
        required: true,
    },
    createdAt: {
        type: Date,
        required: true,
    },
});

module.exports = mongoose.model('Video', videoSchema);
