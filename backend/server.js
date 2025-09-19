// server.js - Startoscope Backend with AI Integration
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const axios = require('axios');
require('dotenv').config();


const app = express();
const PORT = process.env.PORT || 3001;

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({  model: "gemini-1.5-flash" });

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/startoscope', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// File upload setup
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = 'uploads/';
    await fs.mkdir(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowed = ['.pdf', '.doc', '.docx', '.txt', '.ppt', '.pptx'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'));
    }
  }
});

// Database Schemas
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: String,
  createdAt: { type: Date, default: Date.now }
});

const AnalysisSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  companyName: String,
  inputText: String,
  analysis: {
    confidence: Number,
    fundingPotential: String,
    marketSize: String,
    growthRate: String,
    productMarketFit: String,
    competitors: [{
      name: String,
      description: String,
      url: String
    }],
    strengths: [String],
    challenges: [String],
    currency: { type: String, default: 'INR' }
  },
  createdAt: { type: Date, default: Date.now },
  savedToJournal: { type: Boolean, default: false }
});

const User = mongoose.model('User', UserSchema);
const Analysis = mongoose.model('Analysis', AnalysisSchema);

// Auth middleware
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new Error();
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      throw new Error();
    }
    
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Please authenticate' });
  }
};

// Helper function to extract text from files
async function extractTextFromFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  
  try {
    if (ext === '.pdf') {
      const dataBuffer = await fs.readFile(filePath);
      const data = await pdfParse(dataBuffer);
      return data.text;
    } else if (ext === '.docx') {
      const result = await mammoth.extractRawText({ path: filePath });
      return result.value;
    } else if (ext === '.txt') {
      return await fs.readFile(filePath, 'utf8');
    } else {
      // For PPT files, we'd need a pptx parser
      // For now, return a placeholder
      return "PowerPoint content extraction pending implementation";
    }
  } catch (error) {
    console.error('Error extracting text:', error);
    return '';
  }
}

// Helper function to get exchange rate
async function getExchangeRate() {
  try {
    // Using a free API for exchange rates
    const response = await axios.get('https://api.exchangerate-api.com/v4/latest/USD');
    return response.data.rates.INR || 83; // Default to 83 if API fails
  } catch (error) {
    console.error('Exchange rate API error:', error);
    return 83; // Fallback rate
  }
}

// AI Analysis function
async function analyzeStartupWithAI(text, companyName = null) {
  try {
    const prompt = `
    You are an expert venture capitalist analyzing a startup. Based on the following information, provide a detailed analysis:
    
    ${companyName ? `Company Name: ${companyName}` : 'Generate a creative startup name based on the content'}
    
    Content: ${text}
    
    Provide your analysis in the following JSON format (be creative but realistic):
    {
      "companyName": "Generated or provided company name",
      "confidence": 0.75,
      "fundingPotentialINR": "₹2-5 Cr",
      "fundingPotentialUSD": "$250K-600K",
      "marketSizeINR": "₹850 Cr",
      "marketSizeUSD": "$100M",
      "growthRate": "28%",
      "productMarketFit": "Strong/Moderate/Needs Work",
      "competitors": [
        {
          "name": "Real competitor name",
          "description": "Brief description and valuation",
          "url": "actual website URL"
        }
      ],
      "strengths": [
        "List 5 specific strengths based on the content"
      ],
      "challenges": [
        "List 5 specific challenges or areas to improve"
      ],
      "executiveSummary": "2-3 sentence summary of the opportunity"
    }
    
    Focus on the Indian market context first, but include global comparisons. Be specific and actionable.
    `;

    
    const result = await model.generateContent({
      contents: [{ role: "user", parts: [{ text: prompt }] }]
    });

    const aiText = result.response.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!aiText) throw new Error("Gemini returned no text");

    console.log("🔎 RAW GEMINI OUTPUT:\n", aiText);

    const cleaned = aiText.replace(/```json|```/g, "").trim();
    const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }

    throw new Error("Could not parse JSON from Gemini output");
  } catch (error) {
    console.error("AI analysis error:", error);
    return generateFallbackAnalysis(companyName);
  }
}




// Fallback analysis if AI fails
function generateFallbackAnalysis(companyName) {
  const names = ['TechFlow', 'InnovatePro', 'StartupX', 'NextGen Solutions', 'FutureStack'];
  const randomName = companyName || names[Math.floor(Math.random() * names.length)];
  
  return {
    companyName: randomName,
    confidence: 0.72 + Math.random() * 0.15,
    fundingPotentialINR: "₹2-4 Cr",
    fundingPotentialUSD: "$250K-500K",
    marketSizeINR: "₹500 Cr",
    marketSizeUSD: "$60M",
    growthRate: "25%",
    productMarketFit: "Moderate",
    competitors: [
      {
        name: "Freshworks",
        description: "Indian SaaS leader - $1B+ valuation",
        url: "https://freshworks.com"
      },
      {
        name: "Zoho",
        description: "Bootstrapped giant - $1B+ revenue",
        url: "https://zoho.com"
      }
    ],
    strengths: [
      "Strong technical foundation",
      "Clear problem-solution fit",
      "Experienced founding team",
      "Capital efficient operations",
      "Early customer validation"
    ],
    challenges: [
      "Need clearer go-to-market strategy",
      "Competition from established players",
      "Scaling customer acquisition",
      "Building brand awareness",
      "Regulatory compliance requirements"
    ],
    executiveSummary: "Promising early-stage startup with solid fundamentals. Focus on customer acquisition and product differentiation will be key to success."
  };
}

// Routes

// Auth routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    // Basic validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const user = new User({
      email,
      password: hashedPassword,
      name: name || email.split('@')[0]
    });
    
    await user.save();
    
    // Generate token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Analysis routes
app.post('/api/analyze', upload.single('file'), async (req, res) => {
  try {
    let text = '';
    let companyName = req.body.companyName;
    
    // Extract text from file or use provided text
    if (req.file) {
      text = await extractTextFromFile(req.file.path);
      // Clean up uploaded file after processing
      await fs.unlink(req.file.path);
    } else if (req.body.text) {
      text = req.body.text;
    } else {
      return res.status(400).json({ error: 'No content provided' });
    }
    console.log("🚀 Startup idea being analyzed:", text || "(empty)");

    // Run AI analysis
    const analysis = await analyzeStartupWithAI(text, companyName);
    
    // If user is logged in, save to database
    if (req.user) {
      const savedAnalysis = new Analysis({
        userId: req.user._id,
        companyName: analysis.companyName,
        inputText: text.substring(0, 1000), // Save first 1000 chars
        analysis,
        savedToJournal: false
      });
      await savedAnalysis.save();
      analysis.analysisId = savedAnalysis._id;
    }
    
    res.json({
      success: true,
      data: analysis
    });
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ error: 'Analysis failed' });
  }
});

// Currency conversion endpoint
app.get('/api/exchange-rate', async (req, res) => {
  try {
    const rate = await getExchangeRate();
    res.json({
      success: true,
      rate,
      lastUpdated: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get exchange rate' });
  }
});

// Journal routes (protected)
app.get('/api/journal', authMiddleware, async (req, res) => {
  try {
    const analyses = await Analysis.find({ 
      userId: req.user._id,
      savedToJournal: true 
    }).sort({ createdAt: -1 });
    
    res.json({
      success: true,
      data: analyses
    });
  } catch (error) {
    console.error('Journal fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch journal' });
  }
});

app.post('/api/journal/save', authMiddleware, async (req, res) => {
  try {
    const { analysisId } = req.body;
    
    const analysis = await Analysis.findOneAndUpdate(
      { _id: analysisId, userId: req.user._id },
      { savedToJournal: true },
      { new: true }
    );
    
    if (!analysis) {
      return res.status(404).json({ error: 'Analysis not found' });
    }
    
    res.json({
      success: true,
      data: analysis
    });
  } catch (error) {
    console.error('Save to journal error:', error);
    res.status(500).json({ error: 'Failed to save to journal' });
  }
});

app.delete('/api/journal/:id', authMiddleware, async (req, res) => {
  try {
    const result = await Analysis.findOneAndDelete({
      _id: req.params.id,
      userId: req.user._id
    });
    
    if (!result) {
      return res.status(404).json({ error: 'Analysis not found' });
    }
    
    res.json({
      success: true,
      message: 'Analysis deleted'
    });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ error: 'Failed to delete' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});