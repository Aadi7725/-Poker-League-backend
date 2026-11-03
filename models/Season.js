const mongoose = require('mongoose');
const seasonSchema = new mongoose.Schema({
  leagueId: { type: mongoose.Schema.Types.ObjectId, ref: 'League', required: true, index: true },
  name: { type: String, required: true, trim: true }, format: { type: String, default: 'Points League' },
  champion: { type: String, default: '' }, date: { type: String, default: '' }, tournaments: { type: Number, default: 7 },
  standings: [{ name: String, points: { type: Number, default: 0 }, wins: { type: Number, default: 0 }, played: { type: Number, default: 0 }, positions: { type: [Number], default: [] } }]
}, { timestamps: true });
module.exports = mongoose.model('Season', seasonSchema);
