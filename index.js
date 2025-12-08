const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.xdad6f7.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

let usersCollection, servicesCollection, bookingsCollection;

async function run() {
  try {
    await client.connect();
    console.log("Connected to MongoDB");

    const db = client.db(process.env.DB_NAME);
    usersCollection = db.collection("users");
    servicesCollection = db.collection("services");
    bookingsCollection = db.collection("bookings");

    // ===== AUTH =====
    app.post("/api/auth/register", async (req, res) => {
      try {
        const { name, email, password } = req.body;
        if (!name || !email || !password)
          return res.status(400).json({ message: "Name, email and password are required" });

        const exists = await usersCollection.findOne({ email });
        if (exists) return res.status(400).json({ message: "User already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
          name,
          email,
          password: hashedPassword,
          role: "user",
          createdAt: new Date(),
        };

        const result = await usersCollection.insertOne(newUser);
        const insertedUser = await usersCollection.findOne(
          { _id: result.insertedId },
          { projection: { password: 0 } }
        );

        const token = jwt.sign(
          { id: insertedUser._id.toString(), email: insertedUser.email, role: insertedUser.role, name: insertedUser.name },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.status(201).json({ token, user: insertedUser });
      } catch (err) {
        console.error("Register error:", err);
        res.status(500).json({ message: "Registration failed" });
      }
    });

    app.post("/api/auth/login", async (req, res) => {
      try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: "Email and password required" });

        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).json({ message: "User not found" });

        const match = await bcrypt.compare(password, user.password || "");
        if (!match) return res.status(400).json({ message: "Invalid credentials" });

        const safeUser = { ...user };
        delete safeUser.password;

        const token = jwt.sign(
          { id: user._id.toString(), email: user.email, role: user.role, name: user.name },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.json({ token, user: safeUser });
      } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ message: "Login failed" });
      }
    });

    app.post("/api/auth/google-login", async (req, res) => {
      try {
        const { name, email, photo, uid } = req.body;
        if (!email) return res.status(400).json({ message: "Invalid Google user data" });

        let user = await usersCollection.findOne({ email });

        if (!user) {
          const doc = {
            name: name || "Google User",
            email,
            password: "",
            role: "user",
            googleId: uid || null,
            photo: photo || null,
            createdAt: new Date(),
          };
          const insertRes = await usersCollection.insertOne(doc);
          user = await usersCollection.findOne({ _id: insertRes.insertedId }, { projection: { password: 0 } });
        } else {
          user = { ...user };
          delete user.password;
        }

        const token = jwt.sign(
          { id: user._id.toString(), email: user.email, role: user.role, name: user.name },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.json({ token, user });
      } catch (err) {
        console.error("Google login error:", err);
        res.status(500).json({ message: "Google login failed" });
      }
    });

    // ===== DASHBOARD / DATA =====

    // All services
    app.get("/services", async (req, res) => {
      try {
        const services = await servicesCollection.find().toArray();
        res.json(services);
      } catch {
        res.status(500).json({ message: "Failed to fetch services" });
      }
    });

    // All decorators
    app.get("/decorators", async (req, res) => {
      try {
        const decorators = await usersCollection.find({ role: "decorator" }).toArray();
        res.json(decorators);
      } catch {
        res.status(500).json({ message: "Failed to fetch decorators" });
      }
    });

    // Bookings
    app.get("/bookings", async (req, res) => {
      try {
        const bookings = await bookingsCollection.find().toArray();
        res.json(bookings);
      } catch {
        res.status(500).json({ message: "Failed to fetch bookings" });
      }
    });

    // Bookings for a specific user
    app.get("/bookings/my/:userId", async (req, res) => {
      try {
        const { userId } = req.params;
        const bookings = await bookingsCollection.find({ userId }).toArray();
        res.json(bookings);
      } catch {
        res.status(500).json({ message: "Failed to fetch user bookings" });
      }
    });

    // ===== DEFAULT =====
    app.get("/", (req, res) => res.send("StyleDecor Backend Running"));

  } finally {
    // client stays connected
  }
}

run().catch(console.dir);

app.listen(port, () => console.log(`Server running on port ${port}`));
