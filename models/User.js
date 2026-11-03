const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 80 },
  email: { type: String, required: true, trim: true, lowercase: true, unique: true, maxlength: 254 },
  passwordHash: { type: String, required: true },
  leagues: [{ type: mongoose.Schema.Types.ObjectId, ref: 'League' }],
}, { timestamps: true });
module.exports = mongoose.model('User', userSchema);
