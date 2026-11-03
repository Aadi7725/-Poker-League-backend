const mongoose = require('mongoose');
const playerSchema = new mongoose.Schema({
  leagueId: { type: mongoose.Schema.Types.ObjectId, ref: 'League', required: true, index: true },
  name: { type: String, required: true, trim: true, maxlength: 40 },
  totalPoints: { type: Number, default: 0 }
}, { timestamps: true });
playerSchema.index({ leagueId: 1, name: 1 }, { unique: true });
module.exports = mongoose.model('Player', playerSchema);
