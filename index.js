const admin = require("firebase-admin");
const express = require("express");
const app = express();
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
require("dotenv").config();
const stripe = require("stripe")(process.env.PAYMENT_SECRET_KEY);
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Firebase service account
const decodedKey = Buffer.from(process.env.FIREBASE_ADMIN_KEY, 'base64').toString('utf8')
const serviceAccount = JSON.parse(decodedKey);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// MongoDB connection URI
const uri = process.env.MONGO_URI;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();
    const db = client.db("Zap-Shift");
    const usersCollection = db.collection("users");
    const parcelsCollection = db.collection("parcels");
    const paymentsCollection = db.collection("payments");
    const ridersCollection = db.collection("riders");
    const cashoutsCollection = db.collection("cashouts");
    const trackingCollection = db.collection("trakings");

    // Jwt Middleware
    const verifyFBToken = async (req, res, next) => {
      const authHeader = req.headers?.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).send({ message: "Unauthorized Access‼️" });
      }
      const token = authHeader.split(" ")[1];
      // verify token
      try {
        const decodedUser = await admin.auth().verifyIdToken(token);
        req.decodedUser = decodedUser;
        next();
      } catch (error) {
        return res.status(403).send({ message: "Forbidden!" });
      }
    };
    // Verify admin middleware
    const verifyAdmin = async (req, res, next) => {
      try {
        const email = req.decodedUser?.email;

        if (!email) {
          return res
            .status(401)
            .send({ error: "Unauthorized: No decoded user email." });
        }

        const user = await usersCollection.findOne({ email });

        if (!user || user.role !== "admin") {
          return res.status(403).send({ error: "Forbidden: Admins only." });
        }

        req.user = user; // Optional: attach full DB user if needed later
        next();
      } catch (error) {
        console.error("verifyAdmin error:", error);
        res.status(500).send({ error: "Internal Server Error" });
      }
    };

    // Verify Rider middleware
    const verifyRider = async (req, res, next) => {
      try {
        const email = req.decodedUser?.email;

        if (!email) {
          return res
            .status(401)
            .send({ error: "Unauthorized: No decoded user email." });
        }

        const user = await usersCollection.findOne({ email });

        if (!user || user.role !== "rider") {
          return res.status(403).send({ error: "Forbidden: Riders only." });
        }

        req.user = user; // Optional: attach full DB user if needed later
        next();
      } catch (error) {
        console.error("verifyRider error:", error);
        res.status(500).send({ error: "Internal Server Error" });
      }
    };

    // Create users
    app.post("/users", async (req, res) => {
      try {
        const { email } = req.body;
        const userExist = await usersCollection.findOne({ email });
        if (userExist) {
          const updateUser = await usersCollection.updateOne(
            { email },
            { $set: { last_logged_in: new Date() } },
            { upsert: true } // it could be : new Date() insted of updating from login
          );
          return res.status(200).send({
            message: "User already existed. last_logged_in updated!",
            updated: true,
            inserted: false,
            updateUser,
          });
        }
        const newUser = req.body;
        const result = await usersCollection.insertOne(newUser);
        res.send(result);
      } catch {
        res.status(500).send({ message: "Internal server error!" });
      }
    });

    // Searching users by email for managing admins
    app.get("/users/search", async (req, res) => {
      const emailQuery = req.query.email;

      if (!emailQuery) {
        return res.status(401).send({ message: "User email expected!" });
      }
      const regex = new RegExp(emailQuery, "i");

      try {
        const users = await usersCollection
          .find({ email: { $regex: regex } })
          .project({ email: 1, created_at: 1, role: 1 })
          .limit(10)
          .toArray();
        res.send(users);
      } catch (error) {
        res.status(500).send({ message: "Error searching user" });
      }
    });

    // ✅ Make a user admin
    app.patch(
      "/users/admin/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;

        try {
          const result = await usersCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { role: "admin" } }
          );

          if (result.modifiedCount > 0) {
            res.send({ success: true, message: "Admin added." });
          } else {
            res.status(404).send({
              success: false,
              message: "User not found or already admin.",
            });
          }
        } catch (error) {
          res.status(500).send({ error: error.message });
        }
      }
    );

    // remove a admin
    app.patch(
      "/users/remove-admin/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;

        try {
          const result = await usersCollection.updateOne(
            { _id: new ObjectId(id), role: "admin" },
            { $set: { role: "user" } }
          );

          if (result.modifiedCount > 0) {
            res.send({ success: true, message: "Admin role removed." });
          } else {
            res.status(404).send({
              success: false,
              message: "User not found or not an admin.",
            });
          }
        } catch (error) {
          res.status(500).send({ error: error.message });
        }
      }
    );

    // Get user role by email
    app.get("/users/role", verifyFBToken, async (req, res) => {
      const email = req.query.email;

      if (!email || req.decodedUser.email !== email) {
        return res.status(403).send({ error: "Forbidden: Email mismatch" });
      }

      if (!email) {
        return res.status(400).send({ error: "Email is required" });
      }

      try {
        const user = await usersCollection.findOne({ email });

        if (!user) {
          return res.status(404).send({ role: "User not found!" });
        }

        res.send({ role: user.role || "user" });
      } catch (error) {
        res.status(500).send({ error: error.message });
      }
    });

    // ***********************************************************
    // Aggregation
    // Get individual parcel count
    app.get("/parcels/parcel-count", async (req, res) => {
      // const { email } = req.query;
      try {
        const pipeline = [ {
            $group: {
              _id: "$status",
              count: { $sum: 1 },
            },
          },
          {
            $project: {
              status: "$_id",
              count: 1,
              _id: 0,
            },
          }];

        // Add match first if email is provided
        // if (email) {
        //   pipeline.push({
        //     $match: { created_by: email },
        //   });
        // }

        // Then group by status
        // pipeline.push(
         
        // );
        const result = await parcelsCollection.aggregate(pipeline).toArray();
        res.send(result);
      } catch (err) {
        res.status(500).send({ message: "Invalid server" });
      }
    });

    // ****************************************
    // Get all parcels & query by payment and status
    app.get("/parcels", async (req, res) => {
      try {
        const { payment, status } = req.query;

        const query = {};
        if (payment) query.payment = payment;
        if (status) query.status = status;

        const parcels = await parcelsCollection
          .find(query)
          .sort({ created_at: 1 })
          .toArray();

        res.send(parcels);
        //  console.log(query)
      } catch (error) {
        console.error("Error fetching parcels:", error);
        res.status(500).send({ error: "Internal server error" });
      }
    });

    // get my parcels
    app.get("/my-parcel", verifyFBToken, async (req, res) => {
      const userEmail = req.query.email;

      if (!userEmail || req.decodedUser.email !== userEmail) {
        return res.status(403).send({ error: "Forbidden: Email mismatch" });
      }
      try {
        const query = userEmail ? { created_by: userEmail } : {};
        const options = {
          sort: { created_at: -1 },
        };
        const result = await parcelsCollection.find(query, options).toArray();
        res.send(result);
      } catch (error) {
        console.error("Error fetching parcels:", error);
        res.status(500).send("Internal Server Error");
      }
    });

    // Update a parcels status
    app.patch("/parcels/update-status", async (req, res) => {
      const { parcelId, status } = req.body;
      const updateDoc = {
        status: status,
      };
      if (status === "in-transit") {
        updateDoc.picked_at = new Date();
      } else if (status === "delevered") {
        updateDoc.delevered_at = new Date();
      }
      try {
        const result = await parcelsCollection.updateOne(
          { _id: new ObjectId(parcelId) },
          { $set: updateDoc }
        );
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Internal server error!" });
      }
    });

    // Delete a parcel
    app.delete("/parcels/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const result = await parcelsCollection.deleteOne({
          _id: new ObjectId(id),
        });

        res.send(result); // result.deletedCount will be 1 if deleted
      } catch (err) {
        console.error("Error deleting parcel:", err);
        res.status(500).send({ error: "Failed to delete parcel" });
      }
    });

    // Get a single parcel by Id
    app.get("/parcels/:parcelId", async (req, res) => {
      const { parcelId } = req.params;
      const result = await parcelsCollection.findOne({
        _id: new ObjectId(parcelId),
      });
      res.send(result);
    });

    // Create a parcel
    app.post("/parcels", async (req, res) => {
      const newParcel = req.body;
      const result = await parcelsCollection.insertOne(newParcel);
      res.send(result);
    });

    // Create stripe payment intent
    app.post("/create-payment-intent", async (req, res) => {
      const { parcelId } = req.body;
      const parcel = await parcelsCollection.findOne({
        _id: new ObjectId(parcelId),
      });
      try {
        const totalPrice = parcel?.cost * 100;
        const paymentIntent = await stripe.paymentIntents.create({
          amount: totalPrice, // amount in cents
          currency: "usd",
        });
        res.send({ clientSecret: paymentIntent.client_secret });
      } catch (error) {
        res.status(500).send({ error: error.message });
      }
    });

    //** */ Record payment history and update payment status
    app.post("/payments", async (req, res) => {
      const { parcelId, email, amount, paymentMethod, transactionId } =
        req.body;

      if (!email || !parcelId || !amount) {
        return res
          .status(400)
          .send({ message: "Require email, parcelId and amount!" });
      }

      //Update parcel's payment status
      const updateResult = await parcelsCollection.updateOne(
        { _id: new ObjectId(parcelId) },
        { $set: { payment: "paid" } }
      );
      if (updateResult.modifiedCount === 0) {
        return res
          .status(404)
          .send({ message: "Parcel not fount or already paid." });
      }

      // Insert Payment record
      const paymentDoc = {
        parcelId,
        email,
        amount,
        paymentMethod,
        transactionId,
        paid_at: new Date(),
      };

      const paymentResult = await paymentsCollection.insertOne(paymentDoc);

      res
        .status(201)
        .send({ message: "Payment history stores is db", paymentResult });
    });

    //*** Get payment history by user email or all for admin/no email
    app.get("/payments", verifyFBToken, async (req, res) => {
      const userEmail = req.query.email;
      console.log(req.decodedUser);

      const query = userEmail ? { email: userEmail } : {};
      const sort = { sort: { paid_at: -1 } };
      const result = await paymentsCollection.find(query, sort).toArray();
      res.send(result);
    });

    //*** */ Post traking collection
    app.post("/trackings", async (req, res) => {
      const trackingUpdate = req.body;

      if (
        !trackingUpdate.tracking_id ||
        !trackingUpdate.status ||
        !trackingUpdate.updated_by ||
        !trackingUpdate.details
      ) {
        return res.status(400).send({ error: "Required fields missing." });
      }

      trackingUpdate.updatedAt = new Date();

      const result = await trackingCollection.insertOne(trackingUpdate);
      res.send(result);
    });

    // Get a parcel tracking by id
    app.get("/trackings/:trackingId", async (req, res) => {
      const { trackingId } = req.params;
      try {
        const result = await trackingCollection
          .find({ tracking_id: trackingId })
          .sort({ updatedAt: 1 })
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Server error" });
      }
    });

    // ***********************************Rider information
    app.post("/riders", async (req, res) => {
      const rider = req.body;
      const result = await ridersCollection.insertOne(rider);
      res.send(result);
    });

    // Get rider by query email

    app.get("/rider", async (req, res) => {
      try {
        const { email } = req.query;

        if (!email) {
          return res.status(400).send({ error: "Email is required" });
        }

        const rider = await ridersCollection.findOne({ email });

        if (!rider) {
          return res.status(404).send({ error: "Rider not found" });
        }

        res.send(rider);
      } catch (error) {
        console.error("Error fetching rider by email:", error);
        res.status(500).send({ error: "Failed to fetch rider" });
      }
    });

    // ✅ Get riders by district or preferredDistrict
    app.get("/riders", async (req, res) => {
      try {
        const { district, preferredDistrict } = req.query;

        let query = {};

        if (preferredDistrict) {
          query = { preferredDistrict };
        } else if (district) {
          query = { district };
        }

        const riders = await ridersCollection.find(query).toArray();
        res.send(riders);
      } catch (err) {
        console.error("Error fetching riders:", err);
        res.status(500).send({ error: "Failed to fetch riders" });
      }
    });

    // Confirm starting parcel delivary by rider
    app.patch("/assign-rider", async (req, res) => {
      try {
        const { riderId, parcelId } = req.body;
        // Update parcel status
        const updateParcel = await parcelsCollection.updateOne(
          { _id: new ObjectId(parcelId) },
          {
            $set: { status: "rider-assigned", riderId: riderId },
          }
        );
        // Update rider status
        const updateRider = await ridersCollection.updateOne(
          { _id: new ObjectId(riderId) },
          {
            $set: {
              workStatus: "on-work",
            },
          }
        );
        res.send({
          success: true,
          parcelModified: updateParcel.modifiedCount,
          riderModified: updateRider.modifiedCount,
        });
      } catch (err) {
        console.log("Assignment error", err);
        res.status(500).send({ message: "Failed to assign rider" });
      }
    });

    //  return all parcels assigned to a specific rider
    app.get("/rider/pending-delivery/:riderId", async (req, res) => {
      try {
        const { riderId } = req.params;

        const query = {
          riderId,
          status: { $in: ["rider-assigned", "in-transit"] },
        };

        const parcels = await parcelsCollection
          .find(query)
          .sort({ created_at: 1 })
          .toArray();

        res.send(parcels);
      } catch (error) {
        console.error("Error fetching rider's pending parcels:", error);
        res
          .status(500)
          .send({ error: "Failed to fetch rider's delivery tasks" });
      }
    });

    //Get a rider's delivered collection
    app.get(
      "/rider/completed-deliveries/:riderId",
      verifyFBToken,
      verifyRider,
      async (req, res) => {
        try {
          const { riderId } = req.params;

          const query = {
            riderId: riderId,
            status: { $in: ["delivered", "service-center-delivered"] },
          };

          const parcels = await parcelsCollection
            .find(query)
            .sort({ created_at: -1 })
            .toArray();
          res.send(parcels);
        } catch (error) {
          console.error("Error fetching completed deliveries:", error);
          res
            .status(500)
            .send({ error: "Failed to fetch completed deliveries" });
        }
      }
    );

    // Rider cashout requests
    app.post("/cashouts", async (req, res) => {
      const { riderId, riderEmail, amount } = req.body;

      try {
        const newCashout = {
          riderId,
          riderEmail,
          amount,
          status: "pending",
          requested_at: new Date(),
          processed_at: null,
        };
        const result = await cashoutsCollection.insertOne(newCashout);
        res.send({ success: true, id: result.insertedId });
      } catch (err) {
        res
          .status(500)
          .send({ success: false, error: "Failed to request cashout" });
      }
    });

    // Get all cashout request
    app.get("/cashouts", async (req, res) => {
      try {
        const cashouts = await cashoutsCollection
          .find()
          .sort({ requested_at: -1 })
          .toArray();
        res.send(cashouts);
      } catch (err) {
        res.status(500).send({ error: "Failed to fetch cashouts" });
      }
    });

    // Cashout approve or reject by admin
    app.patch("/cashouts/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const { status } = req.body;

        if (!["approved", "rejected"].includes(status)) {
          return res.status(400).send({ error: "Invalid status" });
        }

        const result = await cashoutsCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              status,
              processed_at: new Date(),
            },
          }
        );

        if (result.modifiedCount > 0) {
          res.send({ success: true });
        } else {
          res.status(404).send({ error: "Cashout not found" });
        }
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to update cashout" });
      }
    });

    // Get pending riders
    app.get("/pending-riders", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const query = { status: "pending" };
        const result = await ridersCollection.find(query).toArray();
        res.send(result);
      } catch (error) {
        console.error("Error fetching pending riders:", error);
        res.status(500).send({ message: "Internal Server Error" });
      }
    });

    // Modify pending riders status
    // PATCH /riders/update-status
    app.patch("/riders/update-status", verifyFBToken, async (req, res) => {
      try {
        const { id, status, email } = req.body;

        if (!id || !status) {
          return res
            .status(400)
            .send({ message: "ID and status are required" });
        }

        const result = await ridersCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              status,
              status_updated_at: new Date().toISOString,
            },
          }
        );

        // update user role to rider
        if (status === "active") {
          const userQuery = { email };
          const updatedDoc = {
            $set: {
              role: "rider",
            },
          };
          const roleUpdate = await usersCollection.updateOne(
            userQuery,
            updatedDoc
          );
          res.send(roleUpdate);
        }
        // reject or active riders
        if (result.modifiedCount > 0) {
          return res
            .status(200)
            .send({ message: `Application ${status}`, updated: true });
        } else {
          return res.status(404).send({
            message: "Rider not found or already updated",
            updated: false,
          });
        }
      } catch (error) {
        console.error("Error updating rider status:", error);
        res.status(500).send({ message: "Internal Server Error" });
      }
    });

    // GEt active riders
    app.get("/active-riders", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const result = await ridersCollection
          .find({ status: "active" })
          .sort({ created_at: -1 })
          .toArray();
        res.send(result);
      } catch (error) {
        console.error("Error fetching active riders:", error);
        res.status(500).send({ message: "Internal Server Error" });
      }
    });

    // Parcel Tracking

    // *******************************************

    //********************************************** */
    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    // console.log(
    //   "Pinged your deployment. You successfully connected to MongoDB!"
    // );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", async (req, res) => {
  res.send("Zap shift server is running");
});
// Start server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
