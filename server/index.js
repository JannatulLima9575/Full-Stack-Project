require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const port = process.env.PORT || 3000;
const app = express();

// ✅ Middleware setup
const corsOptions = {
  origin: ['http://localhost:5173', 'http://localhost:5174'],
  credentials: true,
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// ✅ Token verification middleware
const verifyToken = (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) {
    return res.status(401).send({ message: 'unauthorized access' });
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      console.error('JWT Verify Error:', err);
      return res.status(401).send({ message: 'unauthorized access' });
    }
    req.user = decoded;
    next();
  });
};

// ✅ MongoDB setup
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// ✅ Main async function
async function run() {
  try {
    // 🔐 JWT token issue route
    app.post('/jwt', async (req, res) => {
      const { email } = req.body;

      if (!email) {
        return res.status(400).send({ message: 'Email is required' });
      }

      try {
        const token = jwt.sign({ email }, process.env.ACCESS_TOKEN_SECRET, {
          expiresIn: '365d',
        });

        res
          .cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
          })
          .send({ success: true });
      } catch (error) {
        console.error('JWT Error:', error);
        res.status(500).send({ message: 'Internal Server Error' });
      }
    });

    // 🔓 Logout route
    app.get('/logout', async (req, res) => {
      try {
        res
          .clearCookie('token', {
            maxAge: 0,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
          })
          .send({ success: true });
      } catch (err) {
        res.status(500).send({ message: 'Logout Failed', error: err });
      }
    });

    // ✅ Test MongoDB connection
    await client.db('admin').command({ ping: 1 });
    console.log('✅ Connected to MongoDB!');
  } catch (err) {
    console.error('❌ MongoDB connection failed:', err);
  }
}
run().catch(console.dir);

// ✅ Test route
app.get('/', (req, res) => {
  res.send('🌱 Hello from plantNet Server!');
});

// ✅ Server start
app.listen(port, () => {
  console.log(`🚀 plantNet server is running on port ${port}`);
});