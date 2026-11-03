
const mongoose = require("mongoose");

const BlindLevelSchema = new mongoose.Schema(
  {
    sb: { type: Number, required: true, min: 0 },
    bb: { type: Number, required: true, min: 0 },
  },
  { _id: false }
);

const BlindTimerSchema = new mongoose.Schema(
  {
    leagueId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "League",
      required: true,
      unique: true,
      index: true,
    },
    duration: { type: Number, default: 10, min: 1, max: 180 },
    levelIndex: { type: Number, default: 0, min: 0 },
    secondsLeft: { type: Number, default: 600, min: 0 },
    running: { type: Boolean, default: false },
    deadline: { type: Number, default: null },
    levels: {
      type: [BlindLevelSchema],
      default: [
        { sb: 10, bb: 20 },
        { sb: 20, bb: 40 },
        { sb: 30, bb: 60 },
        { sb: 40, bb: 80 },
        { sb: 50, bb: 100 },
        { sb: 75, bb: 150 },
        { sb: 100, bb: 200 },
      ],
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("BlindTimer", BlindTimerSchema);
