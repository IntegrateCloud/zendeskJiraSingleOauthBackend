const mongoose = require('mongoose')
const Schema = mongoose.Schema

const IssueItemSchema = new Schema({
    issueID: {
        type:String,
    },
    customerID: {
        type:String,
        required:true,
    },
    ticketID: {
        type:String,
        required:true,
    },
    projectID:{
        type:String,
        required:true,
    },
    type:{
        type: Boolean,
        default:0,
        required:true,
    }
}, {
    timestamps:true
})
BigInt.prototype.toJSON = function() { return this.toString() }

module.exports = mongoose.model('issueitems', IssueItemSchema)