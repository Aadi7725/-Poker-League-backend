const mongoose = require('mongoose');
const leagueSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 80 },
  inviteCode: { type: String, required: true, unique: true, index: true },
  creator: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  format: { type: String, default: 'Points League' },
  seasonName: { type: String, default: 'Season 01' },
  seasonActive: { type: Boolean, default: true },
  totalMatches: { type: Number, default: 7, min: 1, max: 30 },
  points: { type: [Number], default: [10, 6, 3, 2, 1] },
  champion: { type: String, default: '' },
  finalists: { type: [String], default: [] },
}, { timestamps: true });
module.exports = mongoose.model('League', leagueSchema);
