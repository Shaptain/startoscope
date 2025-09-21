// server.js - Startoscope Backend with Enhanced Authentication
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
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL, 
  credentials: true
}));
app.use(express.json());

// MongoDB connection with better error handling
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/startoscope', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('✅ Connected to MongoDB');
}).catch((error) => {
  console.error('❌ MongoDB connection error:', error);
  process.exit(1);
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
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true, minlength: 6 },
  name: { type: String, trim: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date },
  isActive: { type: Boolean, default: true },
  tokenVersion: { type: Number, default: 0 } // For token invalidation
});

UserSchema.index({ email: 1 });

const AnalysisSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  companyName: String,
  inputText: String,
  analysis: {
    confidence: Number,
    fundingPotentialINR: String,
    fundingPotentialUSD: String,
    marketSizeINR: String,
    marketSizeUSD: String,
    growthRate: String,
    productMarketFit: String,
    competitors: [{
      name: String,
      description: String,
      url: String
    }],
    strengths: [String],
    challenges: [String],
    executiveSummary: String,
    currency: { type: String, default: 'INR' }
  },
  createdAt: { type: Date, default: Date.now },
  savedToJournal: { type: Boolean, default: false }
});

AnalysisSchema.index({ userId: 1, createdAt: -1 });
AnalysisSchema.index({ userId: 1, savedToJournal: 1 });

const ChatHistorySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  sessionId: String,
  messages: [{
    role: { type: String, enum: ['user', 'bot'] },
    content: String,
    timestamp: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

ChatHistorySchema.index({ userId: 1, createdAt: -1 });

const User = mongoose.model('User', UserSchema);
const Analysis = mongoose.model('Analysis', AnalysisSchema);
const ChatHistory = mongoose.model('ChatHistory', ChatHistorySchema);

// Enhanced JWT utilities
const JWT_SECRET = process.env.JWT_SECRET || 'startoscope-super-secret-key-change-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '30d';

const generateTokens = (user) => {
  const payload = {
    userId: user._id,
    email: user.email,
    name: user.name,
    tokenVersion: user.tokenVersion,
    iat: Math.floor(Date.now() / 1000)
  };

  const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
  const refreshToken = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_REFRESH_EXPIRES_IN });

  return { accessToken, refreshToken };
};

const verifyToken = (token) => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return { success: true, data: decoded };
  } catch (error) {
    let errorType = 'INVALID_TOKEN';
    if (error.name === 'TokenExpiredError') {
      errorType = 'TOKEN_EXPIRED';
    } else if (error.name === 'JsonWebTokenError') {
      errorType = 'INVALID_TOKEN';
    }
    
    return { 
      success: false, 
      error: error.message,
      type: errorType
    };
  }
};

// Enhanced Auth middleware with better error handling
const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        success: false,
        error: 'Access denied. No token provided.',
        code: 'NO_TOKEN'
      });
    }
    
    const token = authHeader.substring(7);
    const tokenResult = verifyToken(token);
    
    if (!tokenResult.success) {
      return res.status(401).json({ 
        success: false,
        error: tokenResult.error,
        code: tokenResult.type
      });
    }

    const decoded = tokenResult.data;
    
    // Verify user still exists and is active
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user || !user.isActive) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid token. User not found or inactive.',
        code: 'USER_NOT_FOUND'
      });
    }

    // Check token version for invalidation
    if (decoded.tokenVersion !== user.tokenVersion) {
      return res.status(401).json({ 
        success: false,
        error: 'Token has been invalidated. Please login again.',
        code: 'TOKEN_INVALIDATED'
      });
    }
    
    req.user = user;
    req.token = token;
    req.decoded = decoded;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Authentication service error',
      code: 'AUTH_ERROR'
    });
  }
};

// Optional auth middleware (doesn't fail if no token)
const optionalAuthMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const tokenResult = verifyToken(token);
      
      if (tokenResult.success) {
        const decoded = tokenResult.data;
        const user = await User.findById(decoded.userId).select('-password');
        
        if (user && user.isActive && decoded.tokenVersion === user.tokenVersion) {
          req.user = user;
          req.token = token;
          req.decoded = decoded;
        }
      }
    }
    
    next();
  } catch (error) {
    console.error('Optional auth middleware error:', error);
    next(); // Continue even if there's an error
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
    const response = await axios.get('https://api.exchangerate-api.com/v4/latest/USD');
    return response.data.rates.INR || 83;
  } catch (error) {
    console.error('Exchange rate API error:', error);
    return 83; // Fallback rate
  }
}

// AI Analysis function with enhanced error handling
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

    console.log("🔍 RAW GEMINI OUTPUT:\n", aiText);

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

// Enhanced Chatbot Service
const ChatbotService = {
  systemPrompt: `You are a knowledgeable startup advisor specializing in the Indian and global startup ecosystem.
  Focus on: idea validation, market analysis, funding strategies, business models, growth hacking, and product-market fit.
  Keep responses concise (under 150 words), practical, and actionable. Be encouraging but realistic.
  When relevant, provide Indian market context and examples.`,

  async processMessage(userMessage, userId = null) {
    try {
      const prompt = `
        ${this.systemPrompt}

        User Question: ${userMessage}

        Provide helpful startup advice. If the question is about using Startoscope, explain our analysis features.
      `;

      const result = await model.generateContent(prompt);
      const response = await result.response;
      const botResponse = response.text();

      // Save to chat history if user is logged in
      if (userId) {
        await this.saveChatHistory(userId, userMessage, botResponse);
      }

      return botResponse;
    } catch (error) {
      console.error('Chatbot AI error:', error);
      return this.getFallbackResponse(userMessage);
    }
  },

  async saveChatHistory(userId, userMessage, botResponse) {
    try {
      let chatSession = await ChatHistory.findOne({
        userId,
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      });

      if (!chatSession) {
        chatSession = new ChatHistory({
          userId,
          sessionId: Date.now().toString(),
          messages: []
        });
      }

      chatSession.messages.push(
        { role: 'user', content: userMessage },
        { role: 'bot', content: botResponse }
      );

      await chatSession.save();
    } catch (error) {
      console.error('Chat history save error:', error);
    }
  },

  getFallbackResponse(message) {
    const lowerMessage = message.toLowerCase();

    if (lowerMessage.includes('validate') || lowerMessage.includes('idea')) {
      return "To validate your startup idea: 1) Talk to 20+ potential customers, 2) Identify the specific problem, 3) Test willingness to pay, 4) Build a landing page, 5) Find similar successful startups. Use our analysis tool for detailed validation!";
    }

    if (lowerMessage.includes('funding') || lowerMessage.includes('investor')) {
      return "Indian funding stages: Friends & Family (₹10-25L) → Angel (₹25L-2Cr) → Seed (₹2-10Cr) → Series A (₹10-50Cr). Focus on traction first. Our analysis tool can assess your funding readiness!";
    }

    if (lowerMessage.includes('market') || lowerMessage.includes('research')) {
      return "For market research: Use Google Trends, check NASSCOM/IBEF reports, analyze competitors on Crunchbase, survey your audience. Upload your research to our analyzer for AI-powered insights!";
    }

    if (lowerMessage.includes('mvp') || lowerMessage.includes('product')) {
      return "Build MVP in 4-8 weeks: Focus on ONE core feature, use no-code tools for speed, launch to 10 beta users first. Our analysis can help prioritize features based on market needs.";
    }

    return "I can help with startup questions! Ask about idea validation, funding, market research, MVPs, or business models. For detailed analysis, use our main tool to upload your pitch deck or business plan.";
  }
};

// Input validation helpers
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const validatePassword = (password) => {
  return password && password.length >= 6;
};

const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return input.trim().substring(0, 1000); // Limit input length
};

// ROUTES

// Enhanced Auth Routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    // Validation
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Email and password are required',
        code: 'MISSING_FIELDS'
      });
    }
    
    if (!validateEmail(email)) {
      return res.status(400).json({ 
        success: false,
        error: 'Please provide a valid email address',
        code: 'INVALID_EMAIL'
      });
    }
    
    if (!validatePassword(password)) {
      return res.status(400).json({ 
        success: false,
        error: 'Password must be at least 6 characters long',
        code: 'WEAK_PASSWORD'
      });
    }
    
    // Sanitize inputs
    const cleanEmail = sanitizeInput(email).toLowerCase();
    const cleanName = name ? sanitizeInput(name) : cleanEmail.split('@')[0];
    
    // Check if user exists
    const existingUser = await User.findOne({ email: cleanEmail });
    if (existingUser) {
      return res.status(409).json({ 
        success: false,
        error: 'An account with this email already exists',
        code: 'USER_EXISTS'
      });
    }
    
    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Create user
    const user = new User({
      email: cleanEmail,
      password: hashedPassword,
      name: cleanName,
      lastLogin: new Date()
    });
    
    await user.save();
    
    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);
    
    // Remove password from response
    const userResponse = {
      id: user._id,
      email: user.email,
      name: user.name,
      createdAt: user.createdAt
    };
    
    console.log(`✅ New user registered: ${user.email}`);
    
    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      token: accessToken,
      refreshToken,
      user: userResponse
    });
  } catch (error) {
    console.error('Signup error:', error);
    
    if (error.code === 11000) {
      return res.status(409).json({ 
        success: false,
        error: 'An account with this email already exists',
        code: 'USER_EXISTS'
      });
    }
    
    res.status(500).json({ 
      success: false,
      error: 'Failed to create account. Please try again.',
      code: 'SIGNUP_ERROR'
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validation
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Email and password are required',
        code: 'MISSING_FIELDS'
      });
    }
    
    if (!validateEmail(email)) {
      return res.status(400).json({ 
        success: false,
        error: 'Please provide a valid email address',
        code: 'INVALID_EMAIL'
      });
    }
    
    // Sanitize email
    const cleanEmail = sanitizeInput(email).toLowerCase();
    
    // Find user
    const user = await User.findOne({ email: cleanEmail, isActive: true });
    if (!user) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid email or password',
        code: 'INVALID_CREDENTIALS'
      });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid email or password',
        code: 'INVALID_CREDENTIALS'
      });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);
    
    // Remove password from response
    const userResponse = {
      id: user._id,
      email: user.email,
      name: user.name,
      lastLogin: user.lastLogin
    };
    
    console.log(`✅ User logged in: ${user.email}`);
    
    res.json({
      success: true,
      message: 'Login successful',
      token: accessToken,
      refreshToken,
      user: userResponse
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Login failed. Please try again.',
      code: 'LOGIN_ERROR'
    });
  }
});

// Token verification endpoint
app.get('/api/auth/verify', authMiddleware, async (req, res) => {
  try {
    res.json({
      success: true,
      user: {
        id: req.user._id,
        email: req.user.email,
        name: req.user.name,
        lastLogin: req.user.lastLogin
      }
    });
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Verification failed',
      code: 'VERIFY_ERROR'
    });
  }
});

// Token refresh endpoint
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        error: 'Refresh token required',
        code: 'NO_REFRESH_TOKEN'
      });
    }

    const tokenResult = verifyToken(refreshToken);
    if (!tokenResult.success) {
      return res.status(401).json({
        success: false,
        error: 'Invalid refresh token',
        code: 'INVALID_REFRESH_TOKEN'
      });
    }

    const decoded = tokenResult.data;
    const user = await User.findById(decoded.userId);
    
    if (!user || !user.isActive || decoded.tokenVersion !== user.tokenVersion) {
      return res.status(401).json({
        success: false,
        error: 'Invalid refresh token',
        code: 'INVALID_REFRESH_TOKEN'
      });
    }

    // Generate new tokens
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user);

    res.json({
      success: true,
      token: accessToken,
      refreshToken: newRefreshToken
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      success: false,
      error: 'Token refresh failed',
      code: 'REFRESH_ERROR'
    });
  }
});

// Logout endpoint - invalidates all tokens for user
app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  try {
    // Increment token version to invalidate all existing tokens
    await User.findByIdAndUpdate(req.user._id, { 
      $inc: { tokenVersion: 1 } 
    });

    console.log(`✅ User logged out: ${req.user.email}`);
    
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Logout failed',
      code: 'LOGOUT_ERROR'
    });
  }
});

// Analysis routes
app.post('/api/analyze', optionalAuthMiddleware, upload.single('file'), async (req, res) => {
  try {
    let text = '';
    let companyName = req.body.companyName;
    
    // Extract text from file or use provided text
    if (req.file) {
      text = await extractTextFromFile(req.file.path);
      // Clean up uploaded file after processing
      await fs.unlink(req.file.path).catch(console.error);
    } else if (req.body.text) {
      text = req.body.text;
    } else {
      return res.status(400).json({ 
        success: false,
        error: 'No content provided. Please upload a file or enter text.',
        code: 'NO_CONTENT'
      });
    }
    
    console.log("🚀 Analyzing startup idea:", text.substring(0, 200) + "...");

    // Run AI analysis
    const analysis = await analyzeStartupWithAI(text, companyName);
    
    // If user is logged in, save to database
    let analysisId = null;
    if (req.user) {
      try {
        const savedAnalysis = new Analysis({
          userId: req.user._id,
          companyName: analysis.companyName,
          inputText: text.substring(0, 2000), // Save first 2000 chars
          analysis,
          savedToJournal: false
        });
        
        const saved = await savedAnalysis.save();
        analysisId = saved._id;
        console.log(`✅ Analysis saved for user: ${req.user.email}`);
      } catch (saveError) {
        console.error('Failed to save analysis:', saveError);
        // Don't fail the request if save fails
      }
    }
    
    // Add analysisId to response if available
    if (analysisId) {
      analysis.analysisId = analysisId;
    }
    
    res.json({
      success: true,
      data: analysis,
      message: 'Analysis completed successfully'
    });
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Analysis failed. Please try again.',
      code: 'ANALYSIS_ERROR'
    });
  }
});

// Exchange rate endpoint
app.get('/api/exchange-rate', async (req, res) => {
  try {
    const rate = await getExchangeRate();
    res.json({
      success: true,
      rate,
      lastUpdated: new Date().toISOString()
    });
  } catch (error) {
    console.error('Exchange rate error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to get exchange rate',
      code: 'EXCHANGE_RATE_ERROR'
    });
  }
});

// Enhanced Journal routes (protected)
app.get('/api/journal', authMiddleware, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const analyses = await Analysis.find({ 
      userId: req.user._id,
      savedToJournal: true 
    })
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
    
    const totalCount = await Analysis.countDocuments({
      userId: req.user._id,
      savedToJournal: true
    });
    
    res.json({
      success: true,
      data: analyses,
      pagination: {
        page,
        limit,
        total: totalCount,
        pages: Math.ceil(totalCount / limit)
      }
    });
  } catch (error) {
    console.error('Journal fetch error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch journal entries',
      code: 'JOURNAL_FETCH_ERROR'
    });
  }
});

app.post('/api/journal/save', authMiddleware, async (req, res) => {
  try {
    const { analysisId } = req.body;
    
    if (!analysisId) {
      return res.status(400).json({ 
        success: false,
        error: 'Analysis ID is required',
        code: 'MISSING_ANALYSIS_ID'
      });
    }
    
    const analysis = await Analysis.findOneAndUpdate(
      { _id: analysisId, userId: req.user._id },
      { savedToJournal: true },
      { new: true }
    );
    
    if (!analysis) {
      return res.status(404).json({ 
        success: false,
        error: 'Analysis not found or not authorized',
        code: 'ANALYSIS_NOT_FOUND'
      });
    }
    
    console.log(`✅ Analysis saved to journal: ${req.user.email}`);
    
    res.json({
      success: true,
      data: analysis,
      message: 'Analysis saved to journal successfully'
    });
  } catch (error) {
    console.error('Save to journal error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to save to journal',
      code: 'JOURNAL_SAVE_ERROR'
    });
  }
});

app.delete('/api/journal/:id', authMiddleware, async (req, res) => {
  try {
    const result = await Analysis.findOneAndDelete({
      _id: req.params.id,
      userId: req.user._id
    });
    
    if (!result) {
      return res.status(404).json({ 
        success: false,
        error: 'Analysis not found or not authorized',
        code: 'ANALYSIS_NOT_FOUND'
      });
    }
    
    console.log(`✅ Analysis deleted: ${req.user.email}`);
    
    res.json({
      success: true,
      message: 'Analysis deleted successfully'
    });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to delete analysis',
      code: 'DELETE_ERROR'
    });
  }
});

// Enhanced Chatbot Routes
app.post('/api/chat', optionalAuthMiddleware, async (req, res) => {
  try {
    const { message } = req.body;

    if (!message || message.trim().length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Message is required',
        code: 'EMPTY_MESSAGE'
      });
    }

    if (message.length > 1000) {
      return res.status(400).json({
        success: false,
        error: 'Message too long. Please keep it under 1000 characters.',
        code: 'MESSAGE_TOO_LONG'
      });
    }

    // Process message
    const response = await ChatbotService.processMessage(
      sanitizeInput(message), 
      req.user?._id
    );

    res.json({
      success: true,
      response,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Chat API error:', error);
    res.status(500).json({
      success: false,
      error: 'Chat service temporarily unavailable',
      code: 'CHAT_ERROR'
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});