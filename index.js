const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const admin = require("firebase-admin");
require("dotenv").config();

const app = express();

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017";
const JWT_SECRET = process.env.JWT_SECRET || "yourSuperSecretKey";

const serviceAccount = require("./firebase-service-account.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Middleware
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

// Connect to MongoDB
const client = new MongoClient(MONGO_URI);
let db, usersCollection, itemsCollection, recoveriesCollection;

async function connectDB() {
  await client.connect();
  db = client.db("whereisit");
  usersCollection = db.collection("users");
  itemsCollection = db.collection("items");
  recoveriesCollection = db.collection("recoveries");
  console.log("MongoDB connected (native driver)");
}
connectDB().catch((err) => {
  console.error("MongoDB connection error:", err);
  process.exit(1);
});

// Helper: Basic validation functions
function validateUserData(data) {
  const { name, email, password } = data;
  if (
    !name ||
    typeof name !== "string" ||
    !email ||
    typeof email !== "string" ||
    !password ||
    typeof password !== "string" ||
    password.length < 6
  ) {
    return false;
  }
  return true;
}

function validateItemData(data) {
  const { postType, thumbnail, title, description, category, location, date } =
    data;

  if (
    !postType ||
    (postType !== "lost" && postType !== "found") ||
    !thumbnail ||
    typeof thumbnail !== "string" ||
    !title ||
    typeof title !== "string" ||
    !category ||
    typeof category !== "string" ||
    !location ||
    typeof location !== "string" ||
    !date ||
    isNaN(Date.parse(date))
  ) {
    return false;
  }
  return true;
}

// Auth middleware
const protect = async (req, res, next) => {
  let token;

  // 1. Check Authorization header
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer ")
  ) {
    token = req.headers.authorization.split(" ")[1];

    try {
      // Firebase token
      const decoded = await admin.auth().verifyIdToken(token);
      const { uid, email } = decoded;

      const user = await usersCollection.findOne({ email });
      if (!user) return res.status(404).json({ message: "User not found" });

      req.user = user;
      return next();
    } catch (err) {
      console.error("Firebase token invalid:", err.message);
      return res.status(401).json({ message: "Unauthorized (Firebase)" });
    }
  }

  // 2. Fallback to cookie-based JWT
  token = req.cookies.token;
  if (!token)
    return res.status(401).json({ message: "Unauthorized, no token" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    let user;
    if (decoded.userId) {
      user = await usersCollection.findOne({
        _id: new ObjectId(decoded.userId),
      });
    } else if (decoded.uid) {
      user = await usersCollection.findOne({ uid: decoded.uid });
    }

    if (!user) return res.status(404).json({ message: "User not found" });

    req.user = user;
    next();
  } catch (err) {
    console.error("JWT token invalid:", err.message);
    return res.status(401).json({ message: "Unauthorized (JWT)" });
  }
};

// Helper to create JWT token
const createToken = (userIdOrUid, isUid = false) => {
  if (isUid)
    return jwt.sign({ uid: userIdOrUid }, JWT_SECRET, { expiresIn: "7d" });
  return jwt.sign({ userId: userIdOrUid }, JWT_SECRET, { expiresIn: "7d" });
};

// === Routes ===

// Register
app.post("/api/users/register", async (req, res) => {
  try {
    if (!validateUserData(req.body)) {
      return res.status(400).json({ message: "Invalid user data" });
    }

    const { name, email, password } = req.body;

    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      name,
      email,
      password: hashedPassword,
      uid: null,
    };

    const result = await usersCollection.insertOne(newUser);
    const token = createToken(result.insertedId);

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(201).json({ user: { name, email } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Login
app.post("/api/users/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = createToken(user._id);
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({ user: { name: user.name, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Firebase login
app.post("/api/users/firebase-login", async (req, res) => {
  const { idToken, name } = req.body;

  if (!idToken)
    return res.status(400).json({ message: "No ID token provided" });

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { uid, email } = decodedToken;

    let user = await usersCollection.findOne({ email });

    if (!user) {
      user = {
        email,
        name: name || "Firebase User",
        password: "",
        uid,
      };
      const result = await usersCollection.insertOne(user);
      user._id = result.insertedId;
    } else if (name && user.name !== name) {
      await usersCollection.updateOne({ _id: user._id }, { $set: { name } });
      user.name = name;
    }

    const token = createToken(uid, true);
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      message: "Logged in with Firebase",
      user: { email, uid, name: user.name },
    });
  } catch (error) {
    console.error("Firebase token verification error:", error);
    res.status(401).json({ message: "Invalid Firebase ID token" });
  }
});

// Logout
app.post("/api/users/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  });
  res.json({ message: "Logged out" });
});

// Profile (protected)
app.get("/api/users/profile", protect, async (req, res) => {
  try {
    res.json(req.user);
  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

// Add lost/found item (protected)
app.post("/api/items", protect, async (req, res) => {
  try {
    if (!validateItemData(req.body)) {
      return res.status(400).json({ message: "Invalid item data" });
    }

    const {
      postType,
      thumbnail,
      title,
      description,
      category,
      location,
      date,
    } = req.body;

    const newItem = {
      postType,
      thumbnail,
      title,
      description: description || "",
      category,
      location,
      date: new Date(date),
      contactName: req.user.name,
      contactEmail: req.user.email,
      userId: new ObjectId(req.user._id),
      status: "active",
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await itemsCollection.insertOne(newItem);
    res
      .status(201)
      .json({ message: "Item added successfully", itemId: result.insertedId });
  } catch (err) {
    console.error("Error adding item:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get single item (public)
app.get("/api/items/:id", async (req, res) => {
  try {
    const item = await itemsCollection.findOne({
      _id: new ObjectId(req.params.id),
    });

    if (!item) {
      return res.status(404).json({ message: "Item not found" });
    }

    res.json(item);
  } catch (err) {
    console.error("Error fetching item:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get all items with filters (public)
app.get("/api/items", async (req, res) => {
  try {
    const { type, status, category, location, search } = req.query;
    const query = {};

    if (type && (type === "lost" || type === "found")) {
      query.postType = type;
    }

    if (status && (status === "active" || status === "recovered")) {
      query.status = status;
    }

    if (category) {
      query.category = category;
    }

    if (location) {
      query.location = { $regex: location, $options: "i" };
    }

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
      ];
    }

    const items = await itemsCollection
      .find(query)
      .sort({ createdAt: -1 })
      .toArray();
    res.json(items);
  } catch (err) {
    console.error("Error fetching items:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get items by user (protected)
app.get("/api/items/user/:userId", protect, async (req, res) => {
  try {
    const items = await itemsCollection
      .find({ userId: new ObjectId(req.params.userId) })
      .sort({ createdAt: -1 })
      .toArray();
    res.json(items);
  } catch (err) {
    console.error("Error fetching user items:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Report item recovery (protected)
app.post("/api/items/:id/recover", protect, async (req, res) => {
  try {
    const { recoveredLocation, recoveredDate, notes } = req.body;

    if (!recoveredLocation || !recoveredDate) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Check if item exists and is active
    const item = await itemsCollection.findOne({
      _id: new ObjectId(req.params.id),
    });

    if (!item) {
      return res.status(404).json({ message: "Item not found" });
    }

    if (item.status === "recovered") {
      return res.status(400).json({ message: "Item already recovered" });
    }

    // Create recovery record
    const recoveryData = {
      itemId: new ObjectId(req.params.id),
      originalPostType: item.postType,
      originalOwner: item.contactEmail,
      recoveredBy: {
        userId: new ObjectId(req.user._id),
        name: req.user.name,
        email: req.user.email,
      },
      recoveredLocation,
      recoveredDate: new Date(recoveredDate),
      notes: notes || "",
      createdAt: new Date(),
    };

    // Start transaction
    const session = client.startSession();
    try {
      await session.withTransaction(async () => {
        // Create recovery record
        await recoveriesCollection.insertOne(recoveryData, { session });

        // Update item status
        await itemsCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { status: "recovered", updatedAt: new Date() } },
          { session }
        );
      });
    } finally {
      await session.endSession();
    }

    res.json({ message: "Item recovery recorded successfully" });
  } catch (err) {
    console.error("Error recording recovery:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get recoveries for user (protected)
app.get("/api/recoveries", protect, async (req, res) => {
  try {
    const recoveries = await recoveriesCollection
      .find({
        $or: [
          { "recoveredBy.userId": new ObjectId(req.user._id) },
          { originalOwner: req.user.email },
        ],
      })
      .sort({ createdAt: -1 })
      .toArray();

    // Get item details for each recovery
    const recoveriesWithItems = await Promise.all(
      recoveries.map(async (recovery) => {
        const item = await itemsCollection.findOne({
          _id: new ObjectId(recovery.itemId),
        });
        return { ...recovery, item };
      })
    );

    res.json(recoveriesWithItems);
  } catch (err) {
    console.error("Error fetching recoveries:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get user data (protected)
app.get("/api/users/:id", protect, async (req, res) => {
  try {
    const userId = req.params.id;

    // First try to find by Firebase UID
    let user = await usersCollection.findOne({ uid: userId });

    // If not found by UID, try by MongoDB _id
    if (!user) {
      try {
        user = await usersCollection.findOne(
          { _id: new ObjectId(userId) },
          { projection: { password: 0 } }
        );
      } catch (err) {
        // Ignore invalid ObjectId errors
      }
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Get user's items count
    const itemsCount = await itemsCollection.countDocuments({
      $or: [
        { userId: user._id },
        { userId: new ObjectId(user._id) }, // Handle both string and ObjectId
      ],
    });

    // Get user's recoveries count
    const recoveriesCount = await recoveriesCollection.countDocuments({
      $or: [
        { "recoveredBy.userId": user._id },
        { "recoveredBy.userId": user._id.toString() },
        { originalOwner: user.email },
      ],
    });

    // Remove sensitive data before sending
    const { password, ...userData } = user;

    res.json({
      ...userData,
      stats: {
        itemsPosted: itemsCount,
        recoveries: recoveriesCount,
      },
    });
  } catch (err) {
    console.error("Error fetching user:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Root route
app.get("/", (req, res) => {
  res.send("WhereIsIt backend server running");
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
