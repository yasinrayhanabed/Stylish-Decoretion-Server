const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const path = require("path");
const admin = require("firebase-admin");
const fs = require("fs");

const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 5000;

// const serviceAccount = require("./firebase-admin-key.json");

const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8"
);
const serviceAccount = JSON.parse(decoded);

// Initialize Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const client = new MongoClient(process.env.DB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// --- Cloudinary Config ---
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// --- File Upload Setup ---
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const upload = multer({ storage: multer.memoryStorage() });

const corsOptions = {
  origin: [
    "http://localhost:5173",
    process.env.CLIENT_URL,
  ],
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  credentials: true,
  optionsSuccessStatus: 204,
};
app.use(cors(corsOptions));
app.use(express.json());

let usersCollection, servicesCollection, bookingsCollection, paymentsCollection;

  app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Stylish Decoration API is running 🚀",
  });
});

async function run() {
  try {
    // await client.connect();
    console.log("Connected to MongoDB");

    const db = client.db(process.env.DB_NAME || "style-decor");
    usersCollection = db.collection("users");
    servicesCollection = db.collection("services");
    bookingsCollection = db.collection("bookings");
    paymentsCollection = db.collection("payments");

    // --- Middleware: Auth and Role Checks ---

    const verifyToken = (req, res, next) => {
      const authHeader = req.headers.authorization || req.headers.Authorization;
      if (!authHeader) return res.status(401).json({ message: "Unauthorized" });

      const token = authHeader.split(" ")[1] || authHeader;
      if (!token) return res.status(401).json({ message: "Unauthorized" });

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
      } catch (err) {
        return res.status(403).json({ message: "Invalid token" });
      }
    };

    const requireRole =
      (allowedRoles = []) =>
      (req, res, next) => {
        if (!req.user) return res.status(401).json({ message: "Unauthorized" });
        if (!allowedRoles.includes(req.user.role))
          return res.status(403).json({ message: "Forbidden" });
        next();
      };

    

app.get("/favicon.ico", (req, res) => res.status(204).end());
app.get("/favicon.png", (req, res) => res.status(204).end());



    // -------------------------------------------------------------
    // --- AUTH ROUTES ---
    // -------------------------------------------------------------

    app.post("/api/auth/register", upload.single("photo"), async (req, res) => {
      try {
        const body = { ...(req.body || {}) };
        const { name, email, password } = body;

        if (!name || !email || !password)
          return res
            .status(400)
            .json({ message: "Name, email and password are required" });

        const exists = await usersCollection.findOne({ email });
        if (exists)
          return res.status(400).json({ message: "User already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);

        let photoUrl = body.photo || null; // Use provided photo URL if available

        // If a file is uploaded, upload it to Cloudinary
        if (req.file) {
          const b64 = Buffer.from(req.file.buffer).toString("base64");
          let dataURI = "data:" + req.file.mimetype + ";base64," + b64;

          try {
            const uploadResponse = await cloudinary.uploader.upload(dataURI, {
              resource_type: "auto",
              folder: "stylish-decor/avatars",
            });
            photoUrl = uploadResponse.secure_url;
          } catch (uploadError) {
            console.error(
              "Cloudinary upload failed during registration:",
              uploadError
            );
            // Decide if registration should fail. For now, we'll proceed without a photo.
          }
        }
        const newUser = {
          name,
          email,
          password: hashedPassword,
          role: "user",
          photo: photoUrl,
          createdAt: new Date(),
        };
        const result = await usersCollection.insertOne(newUser);
        const insertedUser = await usersCollection.findOne(
          { _id: result.insertedId },
          { projection: { password: 0 } }
        );

        const token = jwt.sign(
          {
            id: insertedUser._id.toString(),
            email: insertedUser.email,
            role: insertedUser.role,
            name: insertedUser.name,
          },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );
        res.status(201).json({ token, user: insertedUser });
      } catch (err) {
        console.error("Registration failed:", err);
        res.status(500).json({ message: "Registration failed" });
      }
    });

    app.post("/api/auth/login", async (req, res) => {
      try {
        const { email, password } = req.body;
        if (!email || !password)
          return res
            .status(400)
            .json({ message: "Email and password required" });

        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).json({ message: "User not found" });

        if (!user.password)
          return res.status(400).json({ message: "Please login with Google" });

        const match = await bcrypt.compare(password, user.password || "");
        if (!match)
          return res.status(400).json({ message: "Invalid credentials" });

        const safeUser = { ...user };
        delete safeUser.password;

        const token = jwt.sign(
          {
            id: user._id.toString(),
            email: user.email,
            role: user.role,
            name: user.name,
          },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.json({ token, user: safeUser });
      } catch (err) {
        console.error("Login failed:", err);
        res.status(500).json({ message: "Login failed" });
      }
    });

    app.post("/api/auth/google-login", async (req, res) => {
      try {
        const { name, email, photo, uid } = req.body;
        if (!email)
          return res.status(400).json({ message: "Invalid Google user data" });

        let user = await usersCollection.findOne({ email });

        if (!user) {
          const randomSeed = uid || Math.random().toString(36).slice(2, 10);
          const tempPasswordHash = await bcrypt.hash(randomSeed, 10);
          const doc = {
            name: name || "Google User",
            email,
            password: tempPasswordHash,
            role: "user",
            googleId: uid || null,
            photo: photo || null,
            createdAt: new Date(),
          };
          const insertRes = await usersCollection.insertOne(doc);
          user = await usersCollection.findOne(
            { _id: insertRes.insertedId },
            { projection: { password: 0 } }
          );
        } else {
          user = { ...user };
          delete user.password;
        }

        const token = jwt.sign(
          {
            id: user._id.toString(),
            email: user.email,
            role: user.role,
            name: user.name,
          },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.json({ token, user });
      } catch (err) {
        console.error("Google login failed:", err);
        res.status(500).json({ message: "Google login failed" });
      }
    });

    // -------------------------------------------------------------
    // --- USER ROUTES ---
    // -------------------------------------------------------------

    app.get("/api/me", verifyToken, async (req, res) => {
      try {
        if (!ObjectId.isValid(req.user.id)) {
          return res.status(400).json({ message: "Invalid user ID in token" });
        }

        const user = await usersCollection.findOne(
          { _id: new ObjectId(req.user.id) },
          { projection: { password: 0 } }
        );
        if (!user) return res.status(404).json({ message: "User not found" });

        const responseUser = {
          ...user,
          decoratorRequestStatus: user.decoratorRequestStatus || null,
          decoratorRequest: user.decoratorRequest || null,
        };

        res.json(responseUser);
      } catch (err) {
        console.error("Failed to fetch user:", err);
        res.status(500).json({ message: "Failed to fetch user" });
      }
    });

    app.put("/api/users/profile", verifyToken, async (req, res) => {
      try {
        const { name, phone, address } = req.body;

        if (!name) {
          return res.status(400).json({ message: "Name is required" });
        }
        if (!ObjectId.isValid(req.user.id)) {
          return res.status(400).json({ message: "Invalid user ID" });
        }

        const updateData = {
          name,
          phone: phone || null,
          address: address || null,
          updatedAt: new Date(),
        };

        const result = await usersCollection.updateOne(
          { _id: new ObjectId(req.user.id) },
          { $set: updateData }
        );

        if (result.modifiedCount === 0 && result.matchedCount === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        const updatedUser = await usersCollection.findOne(
          { _id: new ObjectId(req.user.id) },
          { projection: { password: 0 } }
        );

        res.json({
          message: "Profile updated successfully",
          user: updatedUser,
        });
      } catch (err) {
        console.error("Failed to update profile:", err);
        res.status(500).json({ message: "Failed to update profile" });
      }
    });

    // -------------------------------------------------------------
    // --- SERVICE ROUTES (RE-ORDERED FOR CORRECTNESS) ---
    // -------------------------------------------------------------

    // GET all services (public)
   // -------------------------------------------------------------
// --- SERVICE ROUTES (FIXED & SAFE) ---
// -------------------------------------------------------------

// GET all services (public)
app.get("/api/services", async (req, res) => {
  try {
    const q = {};
    const { search, category, sort } = req.query;

    if (search) {
      q.$or = [
        { service_name: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
        { category: { $regex: search, $options: "i" } },
      ];
    }

    if (category) q.category = category;

    let cursor = servicesCollection.find(q);

    if (sort === "cost_asc") cursor = cursor.sort({ cost: 1 });
    if (sort === "cost_desc") cursor = cursor.sort({ cost: -1 });

    const services = await cursor.toArray();
    res.json(services);
  } catch (err) {
    console.error("Failed to fetch services:", err);
    res.status(500).json({ message: "Failed to fetch services" });
  }
});

// CREATE service (admin only)
app.post(
  "/api/services",
  verifyToken,
  requireRole(["admin"]),
  upload.single("photo"),
  async (req, res) => {
    try {
      const doc = { ...req.body };

      // 🔥 VERY IMPORTANT — prevent string _id
      delete doc._id;

      if (doc.cost) doc.cost = parseFloat(doc.cost);

      if (
        !doc.service_name ||
        !doc.cost ||
        !doc.category ||
        !doc.description
      ) {
        return res
          .status(400)
          .json({ message: "Missing required service fields" });
      }

      if (req.file) {
        const b64 = Buffer.from(req.file.buffer).toString("base64");
        const dataURI = `data:${req.file.mimetype};base64,${b64}`;

        const uploadRes = await cloudinary.uploader.upload(dataURI, {
          folder: "stylish-decor/services",
        });

        doc.images = [uploadRes.secure_url];
      }

      doc.createdAt = new Date();
      doc.createdBy = new ObjectId(req.user.id);

      const result = await servicesCollection.insertOne(doc);
      res.status(201).json({
        success: true,
        serviceId: result.insertedId,
      });
    } catch (err) {
      console.error("Failed to create service:", err);
      res.status(500).json({ message: "Failed to create service" });
    }
  }
);

// GET single service (BACKWARD COMPATIBLE)
app.get("/api/services/:id", async (req, res) => {
  try {
    const { id } = req.params;

    let query;
    if (ObjectId.isValid(id)) {
      query = { $or: [{ _id: new ObjectId(id) }, { _id: id }] };
    } else {
      query = { _id: id };
    }

    const service = await servicesCollection.findOne(query);

    if (!service) {
      return res.status(404).json({ message: "Service not found" });
    }

    res.json(service);
  } catch (err) {
    console.error("Failed to fetch service:", err);
    res.status(500).json({ message: "Failed to fetch service" });
  }
});

// UPDATE service
app.put(
  "/api/services/:id",
  verifyToken,
  requireRole(["admin"]),
  upload.single("photo"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid service ID" });
      }

      const updateData = { ...req.body };
      delete updateData._id;

      if (updateData.cost) {
        updateData.cost = parseFloat(updateData.cost);
      }

      if (req.file) {
        const b64 = Buffer.from(req.file.buffer).toString("base64");
        const dataURI = `data:${req.file.mimetype};base64,${b64}`;

        const uploadRes = await cloudinary.uploader.upload(dataURI, {
          folder: "stylish-decor/services",
        });

        updateData.images = [uploadRes.secure_url];
      }

      updateData.updatedAt = new Date();

      const result = await servicesCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updateData }
      );

      if (!result.matchedCount) {
        return res.status(404).json({ message: "Service not found" });
      }

      const updated = await servicesCollection.findOne({
        _id: new ObjectId(id),
      });

      res.json({ success: true, service: updated });
    } catch (err) {
      console.error("Failed to update service:", err);
      res.status(500).json({ message: "Failed to update service" });
    }
  }
);

// DELETE service
app.delete(
  "/api/services/:id",
  verifyToken,
  requireRole(["admin"]),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid service ID" });
      }

      const result = await servicesCollection.deleteOne({
        _id: new ObjectId(id),
      });

      if (!result.deletedCount) {
        return res.status(404).json({ message: "Service not found" });
      }

      res.json({ success: true, message: "Service deleted successfully" });
    } catch (err) {
      console.error("Failed to delete service:", err);
      res.status(500).json({ message: "Failed to delete service" });
    }
  }
);

    // -------------------------------------------------------------
    // --- PAYMENT ROUTES ---
    // -------------------------------------------------------------

    app.post("/api/create-payment-intent", verifyToken, async (req, res) => {
      try {
        const { amount } = req.body;
        const amountInCents = Math.round(amount * 100);

        if (isNaN(amountInCents) || amountInCents < 50) {
          // Stripe minimum is ~50 cents
          return res
            .status(400)
            .json({ message: "Invalid amount or amount is too low." });
        }

        const paymentIntent = await stripe.paymentIntents.create({
          amount: amountInCents,
          currency: "bdt",
          payment_method_types: ["card"],
        });

        res.send({
          clientSecret: paymentIntent.client_secret,
        });
      } catch (err) {
        console.error("Failed to create payment intent:", err);
        res.status(500).json({
          message: "Failed to create payment intent on server.",
          errorDetail: err.raw?.message || err.message,
        });
      }
    });

    app.post("/api/payments", verifyToken, async (req, res) => {
      try {
        const { bookingId, transactionId, amount, currency } = req.body;

        if (!bookingId || !transactionId || !amount) {
          return res
            .status(400)
            .json({ message: "Missing required payment data." });
        }

        if (!ObjectId.isValid(bookingId)) {
          return res.status(400).json({ message: "Invalid booking ID." });
        }

        const paymentData = {
          bookingId: new ObjectId(bookingId),
          transactionId,
          amount: parseFloat(amount),
          currency: currency || "bdt",
          userId: req.user.id,
          userEmail: req.user.email,
          paymentDate: new Date(),
        };

        const result = await paymentsCollection.insertOne(paymentData);

        // Update booking status
        await bookingsCollection.updateOne(
          { _id: new ObjectId(bookingId) },
          {
            $set: {
              paymentStatus: "completed",
              status: "Completed",
              transactionId: transactionId,
            },
          }
        );

        res.status(201).json({ success: true, paymentId: result.insertedId });
      } catch (err) {
        console.error("Payment processing failed:", err);
        res.status(500).json({ message: "Payment failed" });
      }
    });

    app.get("/api/payments/:transactionId", verifyToken, async (req, res) => {
      try {
        const { transactionId } = req.params;

        const payment = await paymentsCollection.findOne({
          transactionId: transactionId,
          userId: req.user.id,
        });

        if (!payment) {
          return res
            .status(404)
            .json({ message: "Payment record not found or unauthorized." });
        }

        let bookingDetails = null;
        if (ObjectId.isValid(payment.bookingId)) {
          bookingDetails = await bookingsCollection.findOne(
            { _id: new ObjectId(payment.bookingId) },
            { projection: { userId: 0, userEmail: 0, userName: 0 } }
          );
        }

        res.json({ ...payment, bookingDetails });
      } catch (err) {
        console.error("Failed to fetch payment and booking details:", err);
        res
          .status(500)
          .json({ message: "Failed to fetch payment and booking details." });
      }
    });

    // -------------------------------------------------------------
    // --- BOOKING ROUTES (Correct Routing Order) ---
    // -------------------------------------------------------------

    // Admin: Get all bookings
    app.get(
      "/api/bookings",
      verifyToken,
      requireRole(["admin"]),
      async (req, res) => {
        try {
          const bookings = await bookingsCollection
            .find()
            .sort({ createdAt: -1 })
            .toArray();
          res.json(bookings);
        } catch (err) {
          console.error("Failed to fetch all bookings (admin):", err);
          res.status(500).json({ message: "Failed to fetch bookings" });
        }
      }
    );

    // Get all bookings for the current user (MyBookingsPage)
    app.get("/api/bookings/my", verifyToken, async (req, res) => {
      try {
        const userId = req.user.id;
        const bookings = await bookingsCollection
          .find({ userId: userId })
          .sort({ createdAt: -1 })
          .toArray();
        res.json(bookings);
      } catch (err) {
        console.error("Failed to fetch user bookings:", err);
        res.status(500).json({ message: "Failed to fetch user bookings" });
      }
    });

    // Get all bookings assigned to the decorator
    app.get(
      "/api/bookings/assigned",
      verifyToken,
      requireRole(["decorator"]),
      async (req, res) => {
        try {
          const bookings = await bookingsCollection
            .find({ decoratorId: req.user.id })
            .toArray();
          res.json(bookings);
        } catch (err) {
          console.error("Failed to fetch assigned bookings:", err);
          res
            .status(500)
            .json({ message: "Failed to fetch assigned bookings" });
        }
      }
    );

    // Create a new booking
    app.post(
      "/api/bookings",
      verifyToken,
      requireRole(["user"]),
      async (req, res) => {
        try {
          const bookingData = req.body;

          if (
            !bookingData.serviceId ||
            !bookingData.date ||
            !bookingData.location
          ) {
            return res.status(400).json({
              message:
                "Missing required booking fields (serviceId, date, location).",
            });
          }

          if (!ObjectId.isValid(bookingData.serviceId)) {
            return res.status(400).json({ message: "Invalid service ID." });
          }

          const service = await servicesCollection.findOne({
            _id: new ObjectId(bookingData.serviceId),
          });
          if (!service) {
            return res.status(404).json({ message: "Service not found." });
          }

          const newBooking = {
            ...bookingData,
            userId: req.user.id,
            userName: req.user.name,
            userEmail: req.user.email,
            serviceName: service.service_name,
            cost: service.cost || parseFloat(bookingData.cost),
            status: "Pending",
            paymentStatus: "pending",
            createdAt: new Date(),
            decoratorId: null,
            transactionId: null,
          };

          const result = await bookingsCollection.insertOne(newBooking);
          const createdBooking = await bookingsCollection.findOne({
            _id: result.insertedId,
          });
          res.status(201).json({ success: true, booking: createdBooking });
        } catch (err) {
          console.error("Failed to create booking:", err);
          res.status(500).json({ message: "Failed to create booking" });
        }
      }
    );

    // Get single booking by ID (This must be after other specific GET routes)
    app.get("/api/bookings/:id", verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
          return res
            .status(400)
            .json({ message: "Invalid booking ID format." });
        }

        const booking = await bookingsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!booking) {
          return res.status(404).json({ message: "Booking not found." });
        }

        // Check for authorization
        const isOwner = booking.userId === req.user.id;
        const isAssignedDecorator = booking.decoratorId === req.user.id;
        const isAdmin = req.user.role === "admin";

        if (!isOwner && !isAssignedDecorator && !isAdmin) {
          return res.status(403).json({ message: "Access denied." });
        }

        res.json(booking);
      } catch (err) {
        console.error("Failed to fetch booking details:", err);
        res.status(500).json({ message: "Failed to fetch booking details" });
      }
    });

    // Update booking (Admin/Decorator)
    app.put(
      "/api/bookings/:id",
      verifyToken,
      requireRole(["admin", "decorator"]),
      async (req, res) => {
        try {
          const { id } = req.params;
          const data = req.body;

          if (!ObjectId.isValid(id)) {
            return res.status(400).json({ message: "Invalid booking ID" });
          }

          const updateDoc = { $set: { updatedAt: new Date() } };

          if (req.user.role === "admin" && data.decoratorId) {
            if (!ObjectId.isValid(data.decoratorId)) {
              return res.status(400).json({ message: "Invalid decorator ID" });
            }
            updateDoc.$set.decoratorId = data.decoratorId;
            updateDoc.$set.status = "Assigned";
          }

          if (data.status) {
            updateDoc.$set.status = data.status;
          }

          const result = await bookingsCollection.updateOne(
            { _id: new ObjectId(id) },
            updateDoc
          );

          if (result.matchedCount > 0) {
            const updatedBooking = await bookingsCollection.findOne({
              _id: new ObjectId(id),
            });
            res.json(updatedBooking);
          } else {
            res
              .status(404)
              .json({ message: "Booking not found or no changes made" });
          }
        } catch (err) {
          console.error("Failed to update booking:", err);
          res.status(500).json({ message: "Failed to update booking" });
        }
      }
    );

    // Delete/Cancel booking
    app.delete("/api/bookings/:id", verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id))
          return res.status(400).json({ message: "Invalid id" });

        const booking = await bookingsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!booking)
          return res.status(404).json({ message: "Booking not found" });

        const isOwner = booking.userId === req.user.id;
        const isAdmin = req.user.role === "admin";

        if (!isOwner && !isAdmin)
          return res.status(403).json({ message: "Forbidden" });

        if (isOwner && booking.status !== "Pending") {
          return res.status(403).json({
            message: "Only 'Pending' bookings can be canceled by the user.",
          });
        }

        const result = await bookingsCollection.deleteOne({
          _id: new ObjectId(id),
        });
        if (result.deletedCount === 0) {
          return res.status(404).json({ message: "Booking not found" });
        }
        res.json({ success: true, message: "Booking canceled successfully" });
      } catch (err) {
        console.error("Failed to delete booking:", err);
        res.status(500).json({ message: "Failed to delete booking" });
      }
    });

    // -------------------------------------------------------------
    // --- ADMIN/DECORATOR MANAGEMENT ROUTES ---
    // -------------------------------------------------------------

    app.get(
      "/api/admin/analytics",
      verifyToken,
      requireRole(["admin"]),
      async (req, res) => {
        try {
          const revenueResult = await paymentsCollection
            .aggregate([
              {
                $group: {
                  _id: null,
                  totalRevenue: { $sum: "$amount" },
                  totalTransactions: { $sum: 1 },
                },
              },
            ])
            .toArray();

          const totalRevenue = revenueResult[0]?.totalRevenue || 0;
          const totalBookings = await bookingsCollection.countDocuments();
          const completedBookings = await bookingsCollection.countDocuments({
            status: "Completed",
          });
          const activeDecorators = await usersCollection.countDocuments({
            role: "decorator",
          });

          res.json({
            totalRevenue,
            totalBookings,
            completedBookings,
            activeDecorators,
          });
        } catch (err) {
          console.error("Failed to fetch analytics data:", err);
          res.status(500).json({ message: "Failed to fetch analytics data" });
        }
      }
    );

    app.post("/api/decorator-requests", verifyToken, async (req, res) => {
      try {
        const {
          experience,
          specialty,
          portfolio,
          description,
          phone,
          location,
          expectedRate,
        } = req.body;

        if (!experience || !specialty || !description || !phone || !location) {
          return res.status(400).json({ message: "Missing required fields" });
        }

        const decoratorRequest = {
          userId: req.user.id,
          userName: req.user.name,
          userEmail: req.user.email,
          experience,
          specialty,
          portfolio: portfolio || null,
          description,
          phone,
          location,
          expectedRate: expectedRate ? parseFloat(expectedRate) : null,
          status: "pending",
          createdAt: new Date(),
        };

        const existingRequest = await usersCollection.findOne({
          _id: new ObjectId(req.user.id),
          decoratorRequestStatus: "pending",
        });

        if (existingRequest) {
          return res
            .status(400)
            .json({ message: "You already have a pending decorator request" });
        }

        await usersCollection.updateOne(
          { _id: new ObjectId(req.user.id) },
          {
            $set: {
              decoratorRequest: decoratorRequest,
              decoratorRequestStatus: "pending",
              updatedAt: new Date(),
            },
          }
        );

        res.status(201).json({
          success: true,
          message:
            "Decorator request submitted successfully! We will review and contact you soon.",
        });
      } catch (err) {
        console.error("Failed to submit decorator request:", err);
        res.status(500).json({ message: "Failed to submit decorator request" });
      }
    });

    app.get(
      "/api/decorator-requests",
      verifyToken,
      requireRole(["admin"]),
      async (req, res) => {
        try {
          const usersWithRequests = await usersCollection
            .find({
              decoratorRequestStatus: { $in: ["pending", "rejected"] },
            })
            .project({ password: 0 })
            .toArray();

          const requests = usersWithRequests.map((user) => ({
            _id: user._id, // This is the user ID
            userId: user._id,
            userName: user.name,
            userEmail: user.email,
            ...user.decoratorRequest,
            status: user.decoratorRequestStatus,
          }));

          res.json(requests);
        } catch (err) {
          console.error("Failed to fetch decorator requests:", err);
          res
            .status(500)
            .json({ message: "Failed to fetch decorator requests" });
        }
      }
    );

    app.put(
      "/api/decorator-requests/:id/approve",
      verifyToken,
      requireRole(["admin"]),
      async (req, res) => {
        try {
          const userId = req.params.id;
          if (!ObjectId.isValid(userId)) {
            return res.status(400).json({ message: "Invalid user ID" });
          }

          const result = await usersCollection.updateOne(
            { _id: new ObjectId(userId) },
            {
              $set: {
                role: "decorator",
                decoratorRequestStatus: "approved",
                updatedAt: new Date(),
              },
            }
          );
          if (result.matchedCount === 0) {
            return res
              .status(404)
              .json({ message: "User with request not found" });
          }
          res.json({ success: true, message: "Request approved" });
        } catch (err) {
          console.error("Failed to approve decorator request:", err);
          res
            .status(500)
            .json({ message: "Failed to approve decorator request" });
        }
      }
    );

    app.put(
      "/api/decorator-requests/:id/reject",
      verifyToken,
      requireRole(["admin"]),
      async (req, res) => {
        try {
          const userId = req.params.id;
          if (!ObjectId.isValid(userId)) {
            return res.status(400).json({ message: "Invalid user ID" });
          }

          const result = await usersCollection.updateOne(
            { _id: new ObjectId(userId) },
            {
              $set: {
                decoratorRequestStatus: "rejected",
                updatedAt: new Date(),
              },
            }
          );
          if (result.matchedCount === 0) {
            return res
              .status(404)
              .json({ message: "User with request not found" });
          }
          res.json({ success: true, message: "Request rejected" });
        } catch (err) {
          console.error("Failed to reject decorator request:", err);
          res
            .status(500)
            .json({ message: "Failed to reject decorator request" });
        }
      }
    );

    app.get("/api/decorators/top-rated", async (req, res) => {
      try {
        const decorators = await usersCollection
          .find({ role: "decorator" })
          .project({ password: 0 })
          .limit(4)
          .toArray();

        const topDecorators = decorators.map((decorator, index) => ({
          ...decorator,
          averageRating: 4.5 + index * 0.1,
          totalReviews: 25 + index * 15,
          completedProjects: 50 + index * 20,
          specialty:
            decorator.decoratorRequest?.specialty ||
            decorator.specialization ||
            "Interior Design",
        }));

        res.json({ data: topDecorators });
      } catch (err) {
        console.error("Failed to fetch top decorators:", err);
        res.status(500).json({ message: "Failed to fetch top decorators" });
      }
    });

    app.get(
      "/api/decorators",
      verifyToken,
      requireRole(["admin"]),
      async (req, res) => {
        try {
          const decorators = await usersCollection
            .find({ role: "decorator" })
            .project({ password: 0 })
            .toArray();
          res.json(decorators);
        } catch (err) {
          console.error("Failed to fetch decorators:", err);
          res.status(500).json({ message: "Failed to fetch decorators" });
        }
      }
    );

    app.get(
      "/api/users",
      verifyToken,
      requireRole(["admin"]),
      async (req, res) => {
        try {
          const users = await usersCollection
            .find()
            .project({ password: 0 })
            .toArray();
          res.json(users);
        } catch (err) {
          console.error("Failed to fetch users:", err);
          res.status(500).json({ message: "Failed to fetch users" });
        }
      }
    );

    app.put(
      "/api/users/:id/role",
      verifyToken,
      requireRole(["admin"]),
      async (req, res) => {
        try {
          const { id } = req.params;
          const { role } = req.body;
          if (!ObjectId.isValid(id))
            return res.status(400).json({ message: "Invalid user ID" });
          if (!["user", "decorator", "admin"].includes(role))
            return res.status(400).json({ message: "Invalid role" });
          const result = await usersCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { role } }
          );
          if (result.matchedCount === 0) {
            return res.status(404).json({ message: "User not found" });
          }
          res.json({ success: true, message: "User role updated" });
        } catch (err) {
          console.error("Failed to update user role:", err);
          res.status(500).json({ message: "Failed to update user role" });
        }
      }
    );

    // await client.db("admin").command({ ping: 1 });
    // console.log("Successfully connected to MongoDB and set up routes.");
  // } catch (err) {
  //   console.error("Failed to start the server:", err);
  //   process.exit(1); 
  // }
} finally{}
}
run().catch(console.dir); // Initialize routes and DB connection

// app.listen(port, () => {
//   console.log(`Server is running on http://localhost:${port}`);
// });

module.exports = app; 
