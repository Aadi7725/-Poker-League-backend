const mongoose = require('mongoose');
const resultSchema = new mongoose.Schema({
  player: { type: mongoose.Schema.Types.ObjectId, ref: 'Player', required: true },
  points: { type: Number, default: 0 }, position: { type: Number, min: 1 }
}, { _id: false });
const tournamentSchema = new mongoose.Schema({
  leagueId: { type: mongoose.Schema.Types.ObjectId, ref: 'League', required: true, index: true },
  tournamentNumber: { type: Number, required: true, min: 1, max: 30 },
  results: [resultSchema]
}, { timestamps: true });
tournamentSchema.index({ leagueId: 1, tournamentNumber: 1 }, { unique: true });
module.exports = mongoose.model('Tournament', tournamentSchema);
