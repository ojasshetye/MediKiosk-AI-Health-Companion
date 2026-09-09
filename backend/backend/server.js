const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");

const { initializeApp, cert } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore } = require("firebase-admin/firestore");

const serviceAccount = require("./serviceAccountKey.json");

initializeApp({
  credential: cert(serviceAccount)
});

const auth = getAuth();
const db = getFirestore();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

function clean(value) {
  return String(value || "").trim();
}

async function requireDoctor(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        error: "Authentication required."
      });
    }

    const idToken = header.substring("Bearer ".length);
    const decoded = await auth.verifyIdToken(idToken);

    if (decoded.role !== "doctor") {
      return res.status(403).json({
        success: false,
        error: "Doctor access required."
      });
    }

    req.user = decoded;
    next();

  } catch (error) {
    console.error("Doctor auth verification error:", error);

    return res.status(401).json({
      success: false,
      error: "Invalid or expired authentication token."
    });
  }
}

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "MediKiosk backend is running"
  });
});

// ================================
// PATIENT SIGNUP
// ================================
app.post("/api/patient/signup", async (req, res) => {
  try {
    const {
      abhaId,
      name,
      dob,
      gender,
      phone,
      password
    } = req.body;

    const id = clean(abhaId);

    if (!id || !name || !dob || !gender || !phone || !password) {
      return res.status(400).json({
        success: false,
        error: "All required fields are required."
      });
    }

    if (password.length < 4) {
      return res.status(400).json({
        success: false,
        error: "Password must be at least 4 characters long."
      });
    }

    const patientRef = db.collection("patients").doc(id);
    const patientDoc = await patientRef.get();

    if (patientDoc.exists) {
      return res.status(409).json({
        success: false,
        error: "This ABHA ID is already registered. Please login instead."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const uid = `patient_${id}`;

    try {
      await auth.createUser({
        uid,
        displayName: name
      });
    } catch (error) {
      if (error.code !== "auth/uid-already-exists") {
        throw error;
      }
    }

    await patientRef.set({
      uid,
      abhaId: id,
      name,
      dob,
      gender,
      phone,
      passwordHash,
      role: "patient",
      createdAt: new Date().toISOString()
    });

    res.json({
      success: true,
      message: "Patient registered successfully."
    });

  } catch (error) {
    console.error("Patient signup error:", error);

    res.status(500).json({
      success: false,
      error: "Registration failed."
    });
  }
});

// ================================
// PATIENT LOGIN
// ================================
app.post("/api/patient/login", async (req, res) => {
  try {
    const {
      abhaId,
      password
    } = req.body;

    const id = clean(abhaId);

    if (!id || !password) {
      return res.status(400).json({
        success: false,
        error: "ABHA ID and password are required."
      });
    }

    const patientRef = db.collection("patients").doc(id);
    const patientDoc = await patientRef.get();

    if (!patientDoc.exists) {
      return res.status(401).json({
        success: false,
        error: "Invalid ABHA ID or password."
      });
    }

    const patient = patientDoc.data();

    const passwordCorrect = await bcrypt.compare(
      password,
      patient.passwordHash || ""
    );

    if (!passwordCorrect) {
      return res.status(401).json({
        success: false,
        error: "Invalid ABHA ID or password."
      });
    }

    const uid = patient.uid || `patient_${id}`;

    try {
      await auth.getUser(uid);
    } catch (error) {
      if (error.code === "auth/user-not-found") {
        await auth.createUser({
          uid,
          displayName: patient.name || "Patient"
        });
      } else {
        throw error;
      }
    }

    const customToken = await auth.createCustomToken(uid, {
      role: "patient",
      abhaId: id
    });

    res.json({
      success: true,
      token: customToken,
      patient: {
        abhaId: id,
        name: patient.name || "",
        dob: patient.dob || "",
        gender: patient.gender || "",
        phone: patient.phone || ""
      }
    });

  } catch (error) {
    console.error("Patient login error:", error);

    res.status(500).json({
      success: false,
      error: "Login failed."
    });
  }
});

// ================================
// DOCTOR SIGNUP
// ================================
app.post("/api/doctor/signup", async (req, res) => {
  try {
    const {
      doctorId,
      name,
      dob,
      password
    } = req.body;

    const id = clean(doctorId);

    if (!id || !name || !dob || !password) {
      return res.status(400).json({
        success: false,
        error: "All required fields are required."
      });
    }

    if (password.length < 4) {
      return res.status(400).json({
        success: false,
        error: "Password must be at least 4 characters long."
      });
    }

    const doctorRef = db.collection("doctors").doc(id);
    const doctorDoc = await doctorRef.get();

    if (doctorDoc.exists) {
      return res.status(409).json({
        success: false,
        error: "This Doctor ID is already registered."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const uid = `doctor_${id}`;

    try {
      await auth.createUser({
        uid,
        displayName: name
      });
    } catch (error) {
      if (error.code !== "auth/uid-already-exists") {
        throw error;
      }
    }

    await doctorRef.set({
      uid,
      doctorId: id,
      name,
      dob,
      passwordHash,
      role: "doctor",
      createdAt: new Date().toISOString()
    });

    res.json({
      success: true,
      message: "Doctor registered successfully."
    });

  } catch (error) {
    console.error("Doctor signup error:", error);

    res.status(500).json({
      success: false,
      error: "Doctor registration failed."
    });
  }
});

// ================================
// DOCTOR LOGIN
// ================================
app.post("/api/doctor/login", async (req, res) => {
  try {
    const {
      doctorId,
      password
    } = req.body;

    const id = clean(doctorId);

    if (!id || !password) {
      return res.status(400).json({
        success: false,
        error: "Doctor ID and password are required."
      });
    }

    const doctorRef = db.collection("doctors").doc(id);
    const doctorDoc = await doctorRef.get();

    if (!doctorDoc.exists) {
      return res.status(401).json({
        success: false,
        error: "Invalid Doctor ID or password."
      });
    }

    const doctor = doctorDoc.data();

    const passwordCorrect = await bcrypt.compare(
      password,
      doctor.passwordHash || ""
    );

    if (!passwordCorrect) {
      return res.status(401).json({
        success: false,
        error: "Invalid Doctor ID or password."
      });
    }

    const uid = doctor.uid || `doctor_${id}`;

    try {
      await auth.getUser(uid);
    } catch (error) {
      if (error.code === "auth/user-not-found") {
        await auth.createUser({
          uid,
          displayName: doctor.name || "Doctor"
        });
      } else {
        throw error;
      }
    }

    const customToken = await auth.createCustomToken(uid, {
      role: "doctor",
      doctorId: id
    });

    res.json({
      success: true,
      token: customToken,
      doctor: {
        docId: id,
        name: doctor.name || "",
        dob: doctor.dob || ""
      }
    });

  } catch (error) {
    console.error("Doctor login error:", error);

    res.status(500).json({
      success: false,
      error: "Doctor login failed."
    });
  }
});

// ================================
// DOCTOR: GET PATIENT BY ABHA ID
// ================================
app.get("/api/doctor/patient/:abhaId", requireDoctor, async (req, res) => {
  try {
    const abhaId = clean(req.params.abhaId);

    if (!abhaId) {
      return res.status(400).json({
        success: false,
        error: "ABHA ID is required."
      });
    }

    const patientRef = db.collection("patients").doc(abhaId);
    const patientDoc = await patientRef.get();

    if (!patientDoc.exists) {
      return res.status(404).json({
        success: false,
        error: "No patient found with ABHA ID: " + abhaId
      });
    }

    const patient = patientDoc.data();

    // Never send the password hash to the doctor frontend.
    delete patient.passwordHash;

    const visitsSnapshot = await patientRef
      .collection("visits")
      .orderBy("createdAt", "desc")
      .get();

    const visits = visitsSnapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json({
      success: true,
      patient,
      visits
    });

  } catch (error) {
    console.error("Doctor patient lookup error:", error);

    res.status(500).json({
      success: false,
      error: "Could not retrieve patient history."
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`MediKiosk backend running on port ${PORT}`);
});
