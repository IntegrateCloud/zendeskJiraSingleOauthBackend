const mongoose = require('mongoose')
const Schema = mongoose.Schema

const UserSchema = new Schema({
    jiraUserName: {
        type: String,
    },
    jiraToken: {
        type: String,
    },
    jiraDomain: {
        type: String,
    },
    zendeskUserId: {
        type: String,
        required: true,
        unique: false,
    },
    zendeskEmail: {
        type: String,
        required: true,
    },
    zendeskSubDomain: {
        type: String,
        required: true,
    },
    zendeskToken: {
        type: String,
    },
    zendeskAccessToken: {
        type: String,
    },
    zendeskRefreshToken: {
        type: String,
    },
    zendeskTokenExpiresAt: {
        type: Date,
    },
    authMethod: {
        type: String,
        enum: ['oauth', 'pat'],
    },
    trial: {
        type: Number,
        default: 90
    },
    customerID: {
        type: String,
        unique: true,
        sparse: true,
    },
    workitems: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'WorkItem'
    }

}, {
    timestamps: true
})

module.exports = mongoose.model('users', UserSchema)
