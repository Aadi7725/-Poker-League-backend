
require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const BlindTimer = require("./models/BlindTimer");

const User = require("./models/User");
const League = require("./models/League");
const Player = require("./models/Player");
const Tournament = require("./models/Tournament");
const Season = require("./models/Season");

const app = express();

const allowedOrigins = [
  process.env.CLIENT_ORIGIN,
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "http://192.168.1.37:5173",
].filter(Boolean);
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error(`CORS blocked origin: ${origin}`));
  },
}));

app.use(express.json({ limit: "1mb" }));

// Create a login token
function createToken(user) {
  return jwt.sign(
    { id: user._id.toString() },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// Never return the password hash to the frontend
function safeUser(user) {
  return {
    id: user._id.toString(),
    name: user.name,
    email: user.email
  };
}

// Require a valid login token
async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token) {
      return res.status(401).json({
        message: "Please log in first."
      });
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(401).json({
        message: "Account not found. Please log in again."
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      message: "Session expired or invalid. Please log in again."
    });
  }
}

// Check league membership
async function getActiveLeague(req, res, next) {
  try {
    const leagueId = req.headers["x-league-id"];

    if (!leagueId || !mongoose.isValidObjectId(leagueId)) {
      return res.status(400).json({
        message: "A valid league ID is required."
      });
    }

    const league = await League.findById(leagueId);

    if (!league) {
      return res.status(404).json({
        message: "League not found."
      });
    }

    const isMember = league.members.some(
      (memberId) =>
        memberId.toString() === req.user._id.toString()
    );

    if (!isMember) {
      return res.status(403).json({
        message: "You are not a member of this league."
      });
    }

    req.league = league;
    next();
  } catch (error) {
    next(error);
  }
}

// Only the creator can edit league data
function creatorOnly(req, res, next) {
  if (
    req.league.creator.toString() !==
    req.user._id.toString()
  ) {
    return res.status(403).json({
      message: "Only the league creator can make changes."
    });
  }

  next();
}

async function disconnectSeasonMembers(league) {
  const creatorId = league.creator.toString();

  const formerMemberIds = league.members.filter(
    (memberId) => memberId.toString() !== creatorId
  );

  if (formerMemberIds.length > 0) {
    await User.updateMany(
      { _id: { $in: formerMemberIds } },
      { $pull: { leagues: league._id } }
    );
  }

  league.members = [league.creator];
}


// Basic API checks
app.get("/", (req, res) => {
  res.json({
    message: "Poker League API is running!"
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    database:
      mongoose.connection.readyState === 1
        ? "Connected"
        : "Disconnected"
  });
});

/* ================================
   PART 2: AUTHENTICATION ROUTES
================================ */

// Register a new user

app.post("/api/auth/register", async (req, res, next) => {
  let createdUser = null;
  let createdLeague = null;

  try {
    const { name, email, password } = req.body;

    if (
      typeof name !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        message: "Name, email and password are required.",
      });
    }

    const cleanName = name.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (cleanName.length < 2 || cleanName.length > 80) {
      return res.status(400).json({
        message: "Name must be between 2 and 80 characters.",
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({
        message: "Please enter a valid email address.",
      });
    }

    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({
        message: "Password must be 8 to 72 characters.",
      });
    }

    const existingUser = await User.findOne({
      email: cleanEmail,
    });

    if (existingUser) {
      return res.status(409).json({
        message: "An account with this email already exists.",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    // Create new user.
    createdUser = await User.create({
      name: cleanName,
      email: cleanEmail,
      passwordHash,
      leagues: [],
    });

    // Create a separate personal league for this user.
    createdLeague = await League.create({
      name: `${cleanName}'s League`,
      inviteCode: await generateInviteCode(),
      creator: createdUser._id,
      members: [createdUser._id],
      format: "Points League",
      seasonName: "Season 01",
      seasonActive: true,
      totalMatches: 7,
      points: [10, 6, 3, 2, 1],
    });

    // Create default players inside this personal league only.
    const defaultPlayers = [
      "Aadi",
      "Paras",
      "Sanyam",
      "Sarthak",
      "Yash",
    ];

    await Player.insertMany(
      defaultPlayers.map((playerName) => ({
        leagueId: createdLeague._id,
        name: playerName,
        totalPoints: 0,
      }))
    );

    // Link the new league to the new user.
    await User.findByIdAndUpdate(createdUser._id, {
      $addToSet: {
        leagues: createdLeague._id,
      },
    });

    const populatedUser = await User.findById(createdUser._id)
      .populate("leagues");

    const leagues = (populatedUser?.leagues || []).map((league) => ({
      ...league.toObject(),
      creator: league.creator.toString(),
      isCreator: league.creator.toString() === createdUser._id.toString(),
    }));

    const token = createToken(createdUser);

    return res.status(201).json({
      message: "Account created successfully.",
      token,
      user: safeUser(createdUser),
      leagues,
    });

  } catch (error) {
    // Clean up partially created registration data if creation fails.
    if (createdLeague) {
      await Player.deleteMany({ leagueId: createdLeague._id });
      await League.deleteOne({ _id: createdLeague._id });
    }

    if (createdUser) {
      await User.deleteOne({ _id: createdUser._id });
    }

    if (error.code === 11000) {
      return res.status(409).json({
        message: "An account with this email already exists.",
      });
    }

    next(error);
  }
});



// Log in an existing user
app.post("/api/auth/login", async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        message: "Email and password are required."
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    const user = await User.findOne({
      email: cleanEmail
    });

    if (!user) {
      return res.status(401).json({
        message: "Invalid email or password."
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!passwordMatches) {
      return res.status(401).json({
        message: "Invalid email or password."
      });
    }

    const token = createToken(user);
    const populatedUser = await User.findById(user._id)
  .populate("leagues");

const leagues = (populatedUser?.leagues || []).map((league) => ({
  ...league.toObject(),
  creator: league.creator.toString(),
  isCreator: league.creator.toString() === user._id.toString()
}));

    return res.json({
  message: "Login successful.",
  token,
  user: safeUser(user),
  leagues
});
  } catch (error) {
    next(error);
  }
});


// Get the currently logged-in user's account
app.get("/api/auth/me", authenticate, (req, res) => {
  res.json({
    user: safeUser(req.user)
  });
});

/* ================================
   PART 3: LEAGUE ROUTES
================================ */

// Generate a unique invite code
async function generateInviteCode() {
  for (let attempt = 0; attempt < 10; attempt++) {
    const code = crypto.randomBytes(4)
      .toString("hex")
      .toUpperCase();

    const existing = await League.findOne({
      inviteCode: code
    });

    if (!existing) return code;
  }

  throw new Error("Could not generate a unique invite code.");
}


 // Allow a member to disconnect without deleting league data

app.post(
  "/api/leagues/leave",
  authenticate,
  async (req, res, next) => {
    try {
      const leagueId = req.headers["x-league-id"];

      if (!leagueId || !mongoose.isValidObjectId(leagueId)) {
        return res.status(400).json({
          message: "A valid league ID is required."
        });
      }

      const league = await League.findById(leagueId);

      if (!league) {
        return res.status(404).json({
          message: "League not found."
        });
      }

      const userId = String(req.user._id);
      const creatorId = String(
        league.creator?._id || league.creator
      );

      if (userId === creatorId) {
        return res.status(403).json({
          message: "The creator cannot disconnect from their own league."
        });
      }

      // Remove this user from the league.
      await League.updateOne(
        { _id: league._id },
        { $pull: { members: req.user._id } }
      );

      // Remove the league from this user's account.
      await User.updateOne(
        { _id: req.user._id },
        { $pull: { leagues: league._id } }
      );

      return res.json({
        message: "Disconnected from shared league successfully."
      });

    } catch (error) {
      next(error);
    }
  }
);

// List leagues for the logged-in user
app.get("/api/leagues", authenticate, async (req, res, next) => {
  try {
    const leagues = await League.find({
      members: req.user._id
    }).sort({ createdAt: -1 });

    res.json(leagues.map((league) => ({
      ...league.toObject(),
      creator: league.creator.toString(),
      isCreator: league.creator.toString() === req.user._id.toString()
    })));
  } catch (error) {
    next(error);
  }
});

app.put(
  "/api/auth/profile",
  authenticate,
  async (req, res, next) => {
    try {
      const { name } = req.body;

      if (typeof name !== "string") {
        return res.status(400).json({
          message: "Account name is required.",
        });
      }

      const cleanName = name.trim();

      if (cleanName.length < 2 || cleanName.length > 80) {
        return res.status(400).json({
          message: "Name must be between 2 and 80 characters.",
        });
      }

      const user = await User.findByIdAndUpdate(
        req.user._id,
        { $set: { name: cleanName } },
        { new: true, runValidators: true }
      ).select("_id name email");

      if (!user) {
        return res.status(404).json({
          message: "User account not found.",
        });
      }

      return res.json({
        message: "Account name updated successfully.",
        user: {
          id: user._id.toString(),
          name: user.name,
          email: user.email,
        },
      });
    } catch (error) {
      next(error);
    }
  }
);



// Create a new league
app.post("/api/leagues", authenticate, async (req, res, next) => {
  try {
    const {
      name,
      seasonName,
      totalMatches,
      points,
      format
    } = req.body;

    const cleanName =
      typeof name === "string" ? name.trim() : "";

    if (!cleanName || cleanName.length > 80) {
      return res.status(400).json({
        message: "League name is required (maximum 80 characters)."
      });
    }

    const matches = Number(totalMatches ?? 7);

    if (
      !Number.isInteger(matches) ||
      matches < 1 ||
      matches > 30
    ) {
      return res.status(400).json({
        message: "Total matches must be between 1 and 30."
      });
    }

    const scoring = points ?? [10, 6, 3, 2, 1];

    if (
      !Array.isArray(scoring) ||
      scoring.length !== 5 ||
      scoring.some(
        (value) =>
          !Number.isFinite(value) ||
          value < 0 ||
          value > 1000
      )
    ) {
      return res.status(400).json({
        message: "Scoring must contain five valid non-negative numbers."
      });
    }

    const inviteCode = await generateInviteCode();

    const league = await League.create({
      name: cleanName,
      inviteCode,
      creator: req.user._id,
      members: [req.user._id],
      format:
        typeof format === "string" && format.trim()
          ? format.trim()
          : "Points League",
      seasonName:
        typeof seasonName === "string" && seasonName.trim()
          ? seasonName.trim()
          : "Season 01",
      seasonActive: true,
      totalMatches: matches,
      points: scoring
    });

    await User.findByIdAndUpdate(req.user._id, {
      $addToSet: { leagues: league._id }
    });

    res.status(201).json({
      ...league.toObject(),
      creator: league.creator.toString(),
      isCreator: true,
      message: "League created successfully."
    });
  } catch (error) {
    next(error);
  }
});


// Join a league using its invite code
app.post("/api/leagues/join", authenticate, async (req, res, next) => {
  try {
    const inviteCode =
      typeof req.body.inviteCode === "string"
        ? req.body.inviteCode.trim().toUpperCase()
        : "";

    if (!inviteCode) {
      return res.status(400).json({
        message: "Invite code is required."
      });
    }

    const league = await League.findOne({ inviteCode });

    if (!league) {
      return res.status(404).json({
        message: "Invalid invite code."
      });
    }

    const alreadyMember = league.members.some(
      (memberId) =>
        memberId.toString() === req.user._id.toString()
    );

    if (!alreadyMember) {
      league.members.push(req.user._id);
      await league.save();

      await User.findByIdAndUpdate(req.user._id, {
        $addToSet: { leagues: league._id }
      });
    }

    res.json({
      ...league.toObject(),
      creator: league.creator.toString(),
      isCreator: league.creator.toString() === req.user._id.toString(),
      message: alreadyMember
        ? "You are already a member of this league."
        : "Joined league successfully."
    });
  } catch (error) {
    next(error);
  }
});
app.post(
  "/api/leagues/leave",
  authenticate,
  getActiveLeague,
  async (req, res, next) => {
    try {
      const userId = req.user._id.toString();
      const creatorId = req.league.creator.toString();

      if (userId === creatorId) {
        return res.status(403).json({
          message: "Creator cannot disconnect from their own league."
        });
      }

      req.league.members = req.league.members.filter(
        (memberId) => memberId.toString() !== userId
      );

      await req.league.save();

      await User.findByIdAndUpdate(req.user._id, {
        $pull: { leagues: req.league._id }
      });

      res.json({
        message: "Disconnected from shared league successfully."
      });
    } catch (error) {
      next(error);
    }
  }
);

// Read shared league information (members only)
app.get(
  "/api/leagues/:leagueId",
  authenticate,
  async (req, res, next) => {
    try {
      if (!mongoose.isValidObjectId(req.params.leagueId)) {
        return res.status(400).json({
          message: "Invalid league ID."
        });
      }

      const league = await League.findById(
        req.params.leagueId
      );

      if (!league) {
        return res.status(404).json({
          message: "League not found."
        });
      }

      const isMember = league.members.some(
        (memberId) =>
          memberId.toString() === req.user._id.toString()
      );

      if (!isMember) {
        return res.status(403).json({
          message: "You are not a member of this league."
        });
      }

      res.json({
        league: {
          ...league.toObject(),
          creator: league.creator.toString(),
          isCreator:
            league.creator.toString() === req.user._id.toString()
        }
      });
    } catch (error) {
      next(error);
    }
  }
);
app.put(
  "/api/leagues/settings",
  authenticate,
  getActiveLeague,
  creatorOnly,
  async (req, res, next) => {
    try {
      
const wasSeasonActive = req.league.seasonActive !== false;

      const {
        seasonName,
        seasonActive,
        champion,
        finalists,
        totalMatches,
        format,
        points
      } = req.body;

      if (seasonName !== undefined) {
        if (
          typeof seasonName !== "string" ||
          !seasonName.trim() ||
          seasonName.trim().length > 80
        ) {
          return res.status(400).json({
            message: "Season name must be 1–80 characters."
          });
        }

        req.league.seasonName = seasonName.trim();
      }

      if (seasonActive !== undefined) {
        if (typeof seasonActive !== "boolean") {
          return res.status(400).json({
            message: "seasonActive must be true or false."
          });
        }

        req.league.seasonActive = seasonActive;
      }

      if (totalMatches !== undefined) {
        const count = Number(totalMatches);
        if (!Number.isInteger(count) || count < 1 || count > 30) {
          return res.status(400).json({ message: "Total matches must be between 1 and 30." });
        }
        req.league.totalMatches = count;
      }

      if (format !== undefined) {
        if (typeof format !== "string" || !format.trim() || format.trim().length > 80) {
          return res.status(400).json({ message: "Format must be 1–80 characters." });
        }
        req.league.format = format.trim();
      }

      if (points !== undefined) {
        if (!Array.isArray(points) || points.length !== 5 || points.some((value) => !Number.isFinite(Number(value)) || Number(value) < 0 || Number(value) > 1000)) {
          return res.status(400).json({ message: "Scoring must contain five valid non-negative numbers." });
        }
        req.league.points = points.map(Number);
      }

      if (champion !== undefined) {
        if (typeof champion !== "string") {
          return res.status(400).json({
            message: "Invalid champion."
          });
        }

        req.league.champion = champion.trim();
      }

      if (finalists !== undefined) {
        if (!Array.isArray(finalists)) {
          return res.status(400).json({
            message: "Finalists must be an array."
          });
        }

        req.league.finalists = finalists;
      }

      


      await req.league.save();

      res.json({
        message: "Season settings saved successfully.",
        league: req.league
      });
    } catch (error) {
      next(error);
    }
  }
);

/* ================================
   PART 4: TOURNAMENT & SEASON ROUTES
================================ */

// Get shared league data
app.get(
  "/api/league-data",
  authenticate,
  getActiveLeague,
  async (req, res, next) => {
    try {
      const leagueId = req.league._id;

      const [players, tournaments, seasons] = await Promise.all([
        Player.find({ leagueId }).sort({ createdAt: 1 }),
        Tournament.find({ leagueId })
          .populate("results.player", "name totalPoints")
          .sort({ tournamentNumber: 1 }),
        Season.find({ leagueId }).sort({ createdAt: -1 })
      ]);

      res.json({
        league: {
          ...req.league.toObject(),
          creator: req.league.creator.toString(),
          isCreator:
            req.league.creator.toString() === req.user._id.toString()
        },
        players,
        tournaments,
        seasons
      });
    } catch (error) {
      next(error);
    }
  }
);


// Get players in the active league (the frontend expects a plain array).
// Get players in the active league.
// If the league has no players yet, create the default five.
app.get(
  "/api/players",
  authenticate,
  getActiveLeague,
  async (req, res, next) => {
    try {
      const filter = { leagueId: req.league._id };

      let players = await Player.find(filter).sort({
        createdAt: 1,
      });

      if (players.length === 0) {
        const defaultNames = [
          "Aadi",
          "Paras",
          "Sanyam",
          "Sarthak",
          "Yash",
        ];

        await Player.insertMany(
          defaultNames.map((name) => ({
            leagueId: req.league._id,
            name,
            totalPoints: 0,
          }))
        );

        players = await Player.find(filter).sort({
          createdAt: 1,
        });

        console.log(
          `Created ${players.length} default players for league ${req.league._id}`
        );
      }

      res.json(players);
    } catch (error) {
      next(error);
    }
  }
);

 // Add a player to the active league
app.post(
  "/api/players",
  authenticate,
  getActiveLeague,
  creatorOnly,
  async (req, res, next) => {
    try {
      const name =
        typeof req.body.name === "string"
          ? req.body.name.trim()
          : "";

      if (!name || name.length > 40) {
        return res.status(400).json({
          message: "Player name is required (maximum 40 characters)."
        });
      }

      const escapedName = name.replace(
        /[.*+?^${}()|[\]\\]/g,
        "\\$&"
      );

      const existing = await Player.findOne({
        leagueId: req.league._id,
        name: {
          $regex: `^${escapedName}$`,
          $options: "i"
        }
      });

      if (existing) {
        return res.status(409).json({
          message: "This player already exists in the league."
        });
      }

      const player = await Player.create({
        leagueId: req.league._id,
        name,
        totalPoints: 0
      });

      return res.status(201).json({
        message: "Player added successfully.",
        player
      });
    } catch (error) {
      if (error.code === 11000) {
        return res.status(409).json({
          message: "This player already exists."
        });
      }

      next(error);
    }
  }
);


// Rename a player without changing their historical tournament references.
app.put("/api/players/:id", authenticate, getActiveLeague, creatorOnly, async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: "Invalid player ID." });
    const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
    if (!name || name.length > 40) return res.status(400).json({ message: "Player name is required (maximum 40 characters)." });
    const player = await Player.findOne({ _id: req.params.id, leagueId: req.league._id });
    if (!player) return res.status(404).json({ message: "Player not found." });
    const duplicate = await Player.findOne({ leagueId: req.league._id, name, _id: { $ne: player._id } });
    if (duplicate) return res.status(409).json({ message: "This player name already exists." });
    player.name = name;
    await player.save();
    res.json({ ...player.toObject(), message: "Player renamed successfully." });
  } catch (error) {
    if (error.code === 11000) return res.status(409).json({ message: "This player name already exists." });
    next(error);
  }
});

// Delete a player and remove their result rows, then recalculate everyone’s points.
app.delete("/api/players/:id", authenticate, getActiveLeague, creatorOnly, async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: "Invalid player ID." });
    const player = await Player.findOne({ _id: req.params.id, leagueId: req.league._id });
    if (!player) return res.status(404).json({ message: "Player not found." });
    const playerCount = await Player.countDocuments({ leagueId: req.league._id });
    if (playerCount <= 2) return res.status(400).json({ message: "At least two players must remain in the league." });
    await Tournament.updateMany({ leagueId: req.league._id }, { $pull: { results: { player: player._id } } });
    await Player.deleteOne({ _id: player._id, leagueId: req.league._id });
    const [players, tournaments] = await Promise.all([
      Player.find({ leagueId: req.league._id }), Tournament.find({ leagueId: req.league._id })
    ]);
    const totals = new Map(players.map((p) => [p._id.toString(), 0]));
    for (const tournament of tournaments) for (const result of tournament.results) {
      const id = result.player.toString(); if (totals.has(id)) totals.set(id, totals.get(id) + Number(result.points || 0));
    }
    await Promise.all(players.map((p) => Player.updateOne({ _id: p._id }, { $set: { totalPoints: totals.get(p._id.toString()) || 0 } })));
    res.json({ message: "Player removed.", players: await Player.find({ leagueId: req.league._id }).sort({ createdAt: 1 }) });
  } catch (error) { next(error); }
});

// Save or update a tournament's results


app.put(
  "/api/tournaments/:number",
  authenticate,
  getActiveLeague,
  creatorOnly,
  async (req, res, next) => {
    try {
      const tournamentNumber = Number(req.params.number);

      if (
        !Number.isInteger(tournamentNumber) ||
        tournamentNumber < 1 ||
        tournamentNumber > req.league.totalMatches
      ) {
        return res.status(400).json({
          message: "Invalid tournament number."
        });
      }

      const { results, editPlayerIds = [] } = req.body;

      if (
        !Array.isArray(results) ||
        !Array.isArray(editPlayerIds) ||
        !editPlayerIds.every((id) => typeof id === "string")
      ) {
        return res.status(400).json({
          message: "Invalid tournament results or edit permissions."
        });
      }

      const players = await Player.find({
        leagueId: req.league._id
      });

      const playerMap = new Map(
        players.map((player) => [
          player._id.toString(),
          player
        ])
      );

      const existingTournament = await Tournament.findOne({
        leagueId: req.league._id,
        tournamentNumber
      });

      const existingResults = existingTournament?.results || [];
      const existingMap = new Map(
        existingResults.map((result) => [
          result.player.toString(),
          result
        ])
      );

      const editsAllowed = new Set(editPlayerIds);
      const incomingMap = new Map();

      // Validate each submitted rank.
      for (const result of results) {
        const playerId = String(result.player || "");
        const position = Number(result.position);
        console.log("BACKEND RANK DEBUG:", {
  playerId: String(result.player),
  positionReceived: result.position,
  position,
  leaguePoints: req.league.points,
  pointsForRank: req.league.points[position - 1],
});
        const confirmed = result.confirmed === true;

        if (
          !playerMap.has(playerId) ||
          incomingMap.has(playerId) ||
          !Number.isInteger(position) ||
          position < 1 ||
          position > players.length
        ) {
          return res.status(400).json({
            message: "Each player and finishing rank must be valid."
          });
        }

        const existingResult = existingMap.get(playerId);

        const rankChanged =
          existingResult &&
          (
            Number(existingResult.position) !== position ||
            existingResult.confirmed !== confirmed
          );

        if (
          existingResult?.confirmed === true &&
          rankChanged &&
          !editsAllowed.has(playerId)
        ) {
          return res.status(409).json({
            message:
              "This rank is confirmed. Use Edit before changing it."
          });
        }

        incomingMap.set(playerId, {
          player: playerId,
          position,
          points: Number(req.league.points[position - 1] ?? 0),
          confirmed
        });
      }

      // Preserve saved ranks that were not included in this request.
      const mergedMap = new Map();

      for (const [playerId, saved] of existingMap) {
        mergedMap.set(playerId, {
          player: playerId,
          position: Number(saved.position),
          points: Number(saved.points || 0),
          confirmed: saved.confirmed === true
        });
      }

      // Apply submitted ranks over the preserved results.
      for (const [playerId, result] of incomingMap) {
        mergedMap.set(playerId, result);
      }

      const cleanResults = [...mergedMap.values()].map((result) => ({
  ...result,
  
  points: Number(req.league.points[Number(result.position) - 1] ?? 0),
}));
console.log(
  "TOURNAMENT POINTS DEBUG:",
  {
    leaguePoints: req.league.points,
    results: cleanResults.map((r) => ({
      player: String(r.player),
      position: r.position,
      points: r.points,
      confirmed: r.confirmed,
    })),
  }
);
const seenPositions = new Set();
      // Validate the complete result list, including preserved ranks.
      for (const result of cleanResults) {
        if (
          seenPositions.has(result.position) ||
          result.position < 1 ||
          result.position > players.length
        ) {
          return res.status(409).json({
            message:
              "Two players cannot have the same rank. Please correct the positions."
          });
        }

        seenPositions.add(result.position);
      }

      const tournament = await Tournament.findOneAndUpdate(
        {
          leagueId: req.league._id,
          tournamentNumber
        },
        {
          $set: {
            results: cleanResults
          }
        },
        {
          new: true,
          upsert: true,
          runValidators: true,
          setDefaultsOnInsert: true
        }
      );

      // Recalculate points across all tournaments.
      const allTournaments = await Tournament.find({
        leagueId: req.league._id
      });

      const totals = new Map(
        players.map((player) => [
          player._id.toString(),
          0
        ])
      );

      for (const savedTournament of allTournaments) {
        for (const result of savedTournament.results) {
          const playerId = result.player.toString();

          if (totals.has(playerId)) {
            totals.set(
              playerId,
              totals.get(playerId) + Number(result.points || 0)
            );
          }
        }
      }

      await Promise.all(
        players.map((player) =>
          Player.findByIdAndUpdate(player._id, {
            $set: {
              totalPoints: totals.get(player._id.toString()) || 0
            }
          })
        )
      );

      const updatedPlayers = await Player.find({
        leagueId: req.league._id
      }).sort({ totalPoints: -1, name: 1 });
      console.log(
  "UPDATED PLAYER TOTALS:",
  updatedPlayers.map((p) => ({
    name: p.name,
    totalPoints: p.totalPoints,
  }))
);

      res.json({
        message: "Tournament results saved.",
        tournament,
        completed: cleanResults.length === players.length,
        players: updatedPlayers
      });
    } catch (error) {
      next(error);
    }
  }
);



app.get(
  "/api/tournaments",
  authenticate,
  getActiveLeague,
  async (req, res, next) => {
    try {
      const tournaments = await Tournament.find({ leagueId: req.league._id })
        .populate("results.player", "name totalPoints")
        .sort({ tournamentNumber: 1 });
      res.json(tournaments);
    } catch (error) {
      next(error);
    }
  }
);

// Delete one tournament and recalculate points


app.delete(
  "/api/tournaments/:number",
  authenticate,
  getActiveLeague,
  creatorOnly,
  async (req, res, next) => {
    try {
      const number = Number(req.params.number);
      const currentCount = Math.max(
        1,
        Number(req.league.totalMatches) || 7
      );

      if (
        !Number.isInteger(number) ||
        number < 1 ||
        number > currentCount
      ) {
        return res.status(400).json({
          message: "Invalid tournament number.",
        });
      }

      if (currentCount <= 1) {
        return res.status(400).json({
          message: "At least one tournament must remain.",
        });
      }

      await Tournament.deleteOne({
        leagueId: req.league._id,
        tournamentNumber: number,
      });

      const laterTournaments = await Tournament.find({
        leagueId: req.league._id,
        tournamentNumber: { $gt: number },
      }).sort({ tournamentNumber: 1 });

      for (const tournament of laterTournaments) {
        await Tournament.updateOne(
          { _id: tournament._id },
          {
            $set: {
              tournamentNumber: tournament.tournamentNumber - 1,
            },
          }
        );
      }

      const newTotalMatches = currentCount - 1;

      await League.updateOne(
        { _id: req.league._id },
        { $set: { totalMatches: newTotalMatches } }
      );

      const [players, tournaments] = await Promise.all([
        Player.find({ leagueId: req.league._id }),
        Tournament.find({ leagueId: req.league._id }),
      ]);

      const totals = new Map(
        players.map((player) => [player._id.toString(), 0])
      );

      for (const tournament of tournaments) {
        for (const result of tournament.results) {
          const id = result.player.toString();

          if (totals.has(id)) {
            totals.set(
              id,
              totals.get(id) + Number(result.points || 0)
            );
          }
        }
      }

      await Promise.all(
        players.map((player) =>
          Player.findByIdAndUpdate(player._id, {
            totalPoints: totals.get(player._id.toString()) || 0,
          })
        )
      );

      return res.json({
        message: "Tournament deleted successfully.",
        totalMatches: newTotalMatches,
        tournaments,
        players: await Player.find({
          leagueId: req.league._id,
        }).sort({ totalPoints: -1, name: 1 }),
      });
    } catch (error) {
      next(error);
    }
  }
);




// Clear all current-season tournament results (creator only); keep player names and archived seasons.
app.delete("/api/tournaments", authenticate, getActiveLeague, creatorOnly, async (req, res, next) => {
  try {
    await Tournament.deleteMany({ leagueId: req.league._id });
    await Player.updateMany({ leagueId: req.league._id }, { $set: { totalPoints: 0 } });
    req.league.champion = "";
    req.league.finalists = [];
    await req.league.save();
    res.json({ message: "Current tournament results cleared." });
  } catch (error) { next(error); }
});

// Rename a league's current season
app.patch(
  "/api/season",
  authenticate,
  getActiveLeague,
  creatorOnly,
  async (req, res, next) => {
    try {
      const name =
        typeof req.body.name === "string"
          ? req.body.name.trim()
          : "";

      if (!name || name.length > 80) {
        return res.status(400).json({
          message: "Season name is required."
        });
      }

      req.league.seasonName = name;
      await req.league.save();

      res.json({
        message: "Season renamed.",
        league: req.league
      });
    } catch (error) {
      next(error);
    }
  }
);


// Reset the current season's tournament results
app.post(
  "/api/season/reset",
  authenticate,
  getActiveLeague,
  creatorOnly,
  async (req, res, next) => {
    try {
      await Promise.all([
        Tournament.deleteMany({ leagueId: req.league._id }),
        Player.updateMany(
          { leagueId: req.league._id },
          { $set: { totalPoints: 0 } }
        )
      ]);

      req.league.champion = "";
      req.league.finalists = [];
      req.league.seasonActive = true;
      await req.league.save();

      res.json({
        message: "Season results reset successfully."
      });
    } catch (error) {
      next(error);
    }
  }
);


// Save a completed season to the archive


app.post(
  "/api/season/archive",
  authenticate,
  getActiveLeague,
  creatorOnly,
  async (req, res, next) => {
    try {
      // If this season was already archived, disconnect any
// friends who were left connected by the earlier code.
if (req.league.seasonActive === false) {
  const creatorId = req.league.creator.toString();

  const formerMemberIds = req.league.members.filter(
    (memberId) => memberId.toString() !== creatorId
  );

  if (formerMemberIds.length > 0) {
    await User.updateMany(
      { _id: { $in: formerMemberIds } },
      { $pull: { leagues: req.league._id } }
    );
  }

  req.league.members = [req.league.creator];
  await req.league.save();

  return res.json({
    message: "Season already archived. Friends disconnected."
  });
}
      if (req.league.seasonActive === false) {
        return res.status(409).json({
          message: "This season has already been archived."
        });
      }

      const players = await Player.find({
        leagueId: req.league._id
      });

      const tournaments = await Tournament.find({
        leagueId: req.league._id
      });

      const standings = players
        .map((player) => {
          const playerResults = tournaments.flatMap((tournament) =>
            tournament.results
              .filter(
                (result) =>
                  result.player.toString() === player._id.toString()
              )
              .map((result) => result.position)
          );

          return {
            name: player.name,
            points: Number(player.totalPoints || 0),
            wins: playerResults.filter(
              (position) => position === 1
            ).length,
            played: playerResults.length,
            positions: Array.from(
              { length: players.length },
              (_, index) =>
                playerResults.filter(
                  (position) => position === index + 1
                ).length
            )
          };
        })
        .sort((a, b) => b.points - a.points);

      const champion =
        typeof req.body.champion === "string"
          ? req.body.champion.trim()
          : "";

      if (!champion) {
        return res.status(400).json({
          message: "Select the Grand Final champion first."
        });
      }

      const archivedSeason = await Season.create({
        leagueId: req.league._id,
        name: req.league.seasonName,
        format: req.league.format,
        champion,
        date: new Date().toISOString(),
        tournaments: tournaments.length,
        standings
      });

    req.league.champion = champion;
req.league.seasonActive = false;

const creatorId = req.league.creator.toString();

const formerMemberIds = req.league.members.filter(
  (memberId) => memberId.toString() !== creatorId
);

if (formerMemberIds.length > 0) {
  await User.updateMany(
    { _id: { $in: formerMemberIds } },
    { $pull: { leagues: req.league._id } }
  );
}

req.league.members = [req.league.creator];
await req.league.save();
console.log("ARCHIVE MEMBERSHIP CHECK:", {
  leagueId: req.league._id.toString(),
  creatorId: req.league.creator.toString(),
  membersAfterSave: req.league.members.map(
    (memberId) => memberId.toString()
  ),
  seasonActive: req.league.seasonActive
});
      return res.status(201).json({
        message: "Season archived successfully.",
        season: archivedSeason,
        updated: false
      });
    } catch (error) {
      next(error);
    }
  }
);



// Get archived seasons for the active league (plain array expected by App.jsx).
app.get("/api/seasons", authenticate, getActiveLeague, async (req, res, next) => {
  try {
    res.json(await Season.find({ leagueId: req.league._id }).sort({ createdAt: -1 }));
  } catch (error) { next(error); }
});


 // Update the champion of one archived season
app.patch(
  "/api/seasons/:id/champion",
  authenticate,
  getActiveLeague,
  creatorOnly,
  async (req, res, next) => {
    try {
      const { champion } = req.body;

      if (typeof champion !== "string" || !champion.trim()) {
        return res.status(400).json({
          message: "Please select a valid champion."
        });
      }

      if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({
          message: "Invalid season ID."
        });
      }

      const season = await Season.findOne({
        _id: req.params.id,
        leagueId: req.league._id
      });

      if (!season) {
        return res.status(404).json({
          message: "Archived season not found."
        });
      }

      const playerExists = await Player.findOne({
        leagueId: req.league._id,
        name: champion.trim()
      });

      if (!playerExists) {
        return res.status(400).json({
          message: "That player is not in this league."
        });
      }

      season.champion = champion.trim();
      await season.save();

      res.json({
        message: "Archived champion updated successfully.",
        season
      });
    } catch (error) {
      next(error);
    }
  }
);

// Delete one archived season summary; this does not touch active tournaments.
app.delete("/api/seasons/:id", authenticate, getActiveLeague, creatorOnly, async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: "Invalid season ID." });
    const deleted = await Season.findOneAndDelete({ _id: req.params.id, leagueId: req.league._id });
    if (!deleted) return res.status(404).json({ message: "Archived season not found." });
    res.json({ message: "Archived season deleted." });
  } catch (error) { next(error); }
});

// Delete all archived season summaries for the active league.
app.delete("/api/seasons", authenticate, getActiveLeague, creatorOnly, async (req, res, next) => {
  try {
    const result = await Season.deleteMany({ leagueId: req.league._id });
    res.json({ message: "Archived season history deleted.", deletedCount: result.deletedCount });
  } catch (error) { next(error); }
});

// Clear stats in archived standings without deleting the season records.

app.put(
  "/api/seasons/stats/clear",
  authenticate,
  getActiveLeague,
  creatorOnly,
  async (req, res, next) => {
    try {
      const { playerName, all } = req.body;

      if (
        all !== true &&
        (typeof playerName !== "string" || !playerName.trim())
      ) {
        return res.status(400).json({
          message: "Provide a playerName or set all to true."
        });
      }

      const targetName =
        typeof playerName === "string" ? playerName.trim() : "";

      const seasons = await Season.find({
        leagueId: req.league._id
      });

      for (const season of seasons) {
        // Clear archived player stats
        season.standings = season.standings.map((standing) => {
          if (all === true || standing.name === targetName) {
            return {
              ...standing.toObject(),
              points: 0,
              wins: 0,
              played: 0,
              positions: []
            };
          }

          return standing;
        });

        // Clear champion for the selected player, or every champion
        if (all === true || season.champion === targetName) {
          season.champion = "";
        }

        await season.save();
      }

      res.json({
        message: "Archived stats and applicable champion records cleared."
      });
    } catch (error) {
      next(error);
    }
  }
);

const DEFAULT_BLIND_LEVELS = [
  { sb: 10, bb: 20 },
  { sb: 20, bb: 40 },
  { sb: 30, bb: 60 },
  { sb: 40, bb: 80 },
  { sb: 50, bb: 100 },
  { sb: 75, bb: 150 },
  { sb: 100, bb: 200 },
];

function blindTimerResponse(timer) {
  const now = Date.now();

  return {
    duration: timer.duration,
    levelIndex: timer.levelIndex,
    secondsLeft:
      timer.running && timer.deadline
        ? Math.max(0, Math.ceil((timer.deadline - now) / 1000))
        : timer.secondsLeft,
    running: timer.running,
    deadline: timer.deadline,
    levels: timer.levels.map((level) => ({
      sb: level.sb,
      bb: level.bb,
    })),
  };
}

// All league members can view the timer.
app.get(
  "/api/blind-timer",
  authenticate,
  getActiveLeague,
  async (req, res, next) => {
    try {
      let timer = await BlindTimer.findOne({
        leagueId: req.league._id,
      });

      if (!timer) {
        timer = await BlindTimer.create({
          leagueId: req.league._id,
          levels: DEFAULT_BLIND_LEVELS,
        });
      }

      const now = Date.now();
      let changed = false;

      // Advance levels using the saved server deadline.
      while (
  timer.running &&
  timer.deadline &&
  timer.deadline <= now
) {
        if (timer.levelIndex >= timer.levels.length - 1) {
          timer.running = false;
          timer.deadline = null;
          timer.secondsLeft = 0;
          changed = true;
          break;
        }

        timer.levelIndex += 1;
        timer.deadline += timer.duration * 60 * 1000;
        timer.secondsLeft = Math.max(
          0,
          Math.ceil((timer.deadline - now) / 1000)
        );
        changed = true;
      }

      if (changed) {
        await timer.save();
      }

      res.json({ timer: blindTimerResponse(timer) });
    } catch (error) {
      next(error);
    }
  }
);

// Only the league creator can change timer settings or controls.
app.put(
  "/api/blind-timer",
  authenticate,
  getActiveLeague,
  creatorOnly,
  async (req, res, next) => {
    try {
      const duration = Number(req.body.duration);
      const levelIndex = Number(req.body.levelIndex);
      const secondsLeft = Number(req.body.secondsLeft);
      const running = req.body.running;
      const levels = req.body.levels;

      if (
        !Number.isInteger(duration) ||
        duration < 1 ||
        duration > 180
      ) {
        return res.status(400).json({
          message: "Level duration must be between 1 and 180 minutes.",
        });
      }

      if (
        !Array.isArray(levels) ||
        levels.length < 1 ||
        levels.length > 100 ||
        levels.some(
          (level) =>
            !Number.isFinite(Number(level.sb)) ||
            Number(level.sb) < 0 ||
            Number(level.sb) > 1000000 ||
            !Number.isFinite(Number(level.bb)) ||
            Number(level.bb) < 0 ||
            Number(level.bb) > 1000000
        )
      ) {
        return res.status(400).json({
          message: "Blind levels are invalid.",
        });
      }

      if (
        !Number.isInteger(levelIndex) ||
        levelIndex < 0 ||
        levelIndex >= levels.length
      ) {
        return res.status(400).json({
          message: "Current blind level is invalid.",
        });
      }

      if (
        !Number.isFinite(secondsLeft) ||
        secondsLeft < 0 ||
        secondsLeft > duration * 60 ||
        typeof running !== "boolean"
      ) {
        return res.status(400).json({
          message: "Timer state is invalid.",
        });
      }

      const timer = await BlindTimer.findOneAndUpdate(
        { leagueId: req.league._id },
        {
          $set: {
            duration,
            levelIndex,
            secondsLeft: Math.floor(secondsLeft),
            running,
            deadline: running
              ? Date.now() + Math.max(0, secondsLeft) * 1000
              : null,
            levels: levels.map((level) => ({
              sb: Number(level.sb),
              bb: Number(level.bb),
            })),
          },
          $setOnInsert: {
            leagueId: req.league._id,
          },
        },
        {
          new: true,
          upsert: true,
          runValidators: true,
          setDefaultsOnInsert: true,
        }
      );

      res.json({
        timer: blindTimerResponse(timer),
        message: "Blind Timer synced.",
      });
    } catch (error) {
      next(error);
    }
  }
);


/* ================================
   SHARED BLIND TIMER ROUTES
================================ */

// Get the shared timer for the active league
app.get(
  "/api/blind-timer",
  authenticate,
  getActiveLeague,
  async (req, res, next) => {
    try {
      let timer = await BlindTimer.findOne({
        leagueId: req.league._id,
      });

      if (!timer) {
        timer = await BlindTimer.create({
          leagueId: req.league._id,
        });
      }

      // Automatically advance the timer if its deadline has passed
      if (timer.running && timer.deadline) {
        const now = Date.now();

        while (
          timer.running &&
          timer.deadline &&
          new Date(timer.deadline).getTime() <= now
        ) {
          if (timer.levelIndex >= timer.levels.length - 1) {
            timer.running = false;
            timer.secondsLeft = 0;
            timer.deadline = null;
            break;
          }

          timer.levelIndex += 1;

          const durationMs =
            Math.max(1, Number(timer.duration) || 10) * 60 * 1000;

         timer.deadline = timer.deadline + durationMs;

         timer.secondsLeft = Math.max(
  0,
  Math.ceil((timer.deadline - now) / 1000)
);
        }

        await timer.save();
      }

      return res.json({ timer });
    } catch (error) {
      next(error);
    }
  }
);

// Save shared timer settings and controls
app.put(
  "/api/blind-timer",
authenticate,
getActiveLeague,
async (req, res, next) => {
    try {
      const {
        duration,
        levelIndex,
        secondsLeft,
        running,
        levels,
      } = req.body;

      const safeDuration = Math.max(
        1,
        Math.min(180, Number(duration) || 10)
      );

      if (!Array.isArray(levels) || levels.length < 1) {
        return res.status(400).json({
          message: "At least one blind level is required.",
        });
      }

      const safeLevels = levels.map((level) => ({
        sb: Math.max(0, Number(level.sb) || 0),
        bb: Math.max(0, Number(level.bb) || 0),
      }));

      const safeLevelIndex = Math.max(
        0,
        Math.min(safeLevels.length - 1, Number(levelIndex) || 0)
      );

      const safeSecondsLeft = Math.max(
        0,
        Number(secondsLeft) || 0
      );

      const timer = await BlindTimer.findOneAndUpdate(
        { leagueId: req.league._id },
        {
          $set: {
            duration: safeDuration,
            levelIndex: safeLevelIndex,
            secondsLeft: safeSecondsLeft,
            running: Boolean(running),
            levels: safeLevels,
          deadline: running
  ? Date.now() + safeSecondsLeft * 1000
  : null,
          },
        },
        {
          new: true,
          upsert: true,
          runValidators: true,
          setDefaultsOnInsert: true,
        }
      );

      return res.json({ timer });
    } catch (error) {
      next(error);
    }
  }
);


// Central error handler
app.use((error, req, res, next) => {
  console.error("API error:", error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    message: "An unexpected server error occurred."
  });
});


// Start only after MongoDB connects
async function startServer() {
  try {
    if (!process.env.MONGODB_URI) {
      throw new Error("MONGODB_URI is missing from .env");
    }

    if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
      throw new Error("JWT_SECRET must be at least 32 characters.");
    }

    await mongoose.connect(process.env.MONGODB_URI);

    console.log("MongoDB connected successfully!");

    const PORT = process.env.PORT || 5000;

    app.listen(PORT, () => {
      console.log(`Server running at http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("Backend failed to start:", error.message);
    process.exit(1);
  }
}

startServer();
