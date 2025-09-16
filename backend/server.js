const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3001;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('uploads'));

// File upload configuration
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Enhanced AI Analysis Generator
class StartoscopeAnalyst {
  static generateDealNotes(companyName = "Your Startup") {
    return {
      companyOverview: {
        name: companyName,
        stage: "Pre-Seed/Seed",
        sector: "B2B SaaS",
        founded: "2024",
        employees: "2-10",
        location: "Remote-first"
      },
      founderAnalysis: {
        experience: "Technical founders with complementary skills. Strong domain expertise.",
        passion: "Clear vision for solving real market pain points. Authentic passion evident.",
        redFlags: "First-time founders, may need advisory support",
        confidence: 0.75 + Math.random() * 0.15 // 75-90% range
      },
      marketAnalysis: {
        size: "$8.5B TAM",
        growth: "28% CAGR",
        competition: "Moderate - established players but room for innovation",
        positioning: "AI-first approach provides competitive advantage"
      },
      traction: {
        revenue: "$10K MRR",
        growth: "25% MoM",
        customers: "15 pilot customers",
        churn: "5% monthly"
      },
      dealNotes: [
        "Strong product vision with clear differentiation",
        "Technical expertise allows for rapid iteration",
        "Need to strengthen go-to-market strategy",
        "Advisory board would add credibility",
        "Unit economics promising but need more data"
      ]
    };
  }

  static generateRiskAssessment() {
    return {
      riskScore: 6.2,
      riskLevel: "Medium",
      criticalRisks: [
        {
          type: "Market Risk",
          severity: "Medium", 
          description: "Highly competitive market with established players",
          impact: "Customer acquisition challenges"
        },
        {
          type: "Execution Risk",
          severity: "Low",
          description: "Small team may struggle with rapid scaling",
          impact: "Growth limitations"
        },
        {
          type: "Financial Risk", 
          severity: "Medium",
          description: "Limited runway without additional funding",
          impact: "12-18 months to profitability"
        }
      ],
      positiveSignals: [
        "Strong early customer feedback",
        "Lean operation with good capital efficiency",
        "Clear path to profitability",
        "Founders show coachability and adaptability"
      ]
    };
  }

  static generateCompetitorAnalysis() {
    const competitors = [
      {
        name: "Notion",
        url: "https://notion.so",
        funding: "$343M raised",
        valuation: "$10B",
        strengths: "All-in-one workspace, strong brand",
        weaknesses: "Complex for simple use cases",
        differentiation: "We focus on specific workflow automation"
      },
      {
        name: "Airtable",
        url: "https://airtable.com",
        funding: "$1.36B raised",
        valuation: "$11B",
        strengths: "Powerful database features",
        weaknesses: "Steep learning curve",
        differentiation: "AI-powered insights out of the box"
      },
      {
        name: "Monday.com",
        url: "https://monday.com",
        funding: "$574M raised",
        valuation: "$7B market cap",
        strengths: "Enterprise features",
        weaknesses: "Expensive for small teams",
        differentiation: "Better pricing for startups"
      },
      {
        name: "ClickUp",
        url: "https://clickup.com",
        funding: "$537M raised",
        valuation: "$4B",
        strengths: "Feature-rich platform",
        weaknesses: "Can be overwhelming",
        differentiation: "Simpler, focused solution"
      },
      {
        name: "Linear",
        url: "https://linear.app",
        funding: "$52M raised",
        valuation: "$400M+",
        strengths: "Great UX for developers",
        weaknesses: "Limited to eng teams",
        differentiation: "Cross-functional team support"
      }
    ];
    
    return {
      directCompetitors: competitors.slice(0, 5),
      marketPosition: "Emerging player in workflow automation space",
      competitiveAdvantages: [
        "AI-native architecture from day one",
        "Simplified onboarding (5 minutes vs 1 hour)",
        "50% lower price point than enterprise solutions",
        "Mobile-first design"
      ]
    };
  }

  static generateFundingAnalysis() {
    return {
      fundingLikelihood: 0.75 + Math.random() * 0.15,
      recommendedRound: "$500K - $2M Pre-seed/Seed",
      timeline: "3-6 months",
      valuation: "$5M - $10M pre-money",
      recommendedInvestors: [
        {
          name: "Y Combinator",
          match: 0.85,
          reason: "Strong fit for B2B SaaS, technical founders"
        },
        {
          name: "First Round Capital",
          match: 0.82,
          reason: "Thesis match, seed stage focus"
        },
        {
          name: "Initialized Capital",
          match: 0.78,
          reason: "Developer tools and productivity focus"
        }
      ],
      prerequisitesForSuccess: [
        "Reach $25K MRR before raising",
        "Secure 2-3 notable angel investors",
        "Build advisory board with domain experts",
        "Create compelling product demo",
        "Document clear go-to-market strategy"
      ]
    };
  }

  static generateGrowthProjections() {
    return {
      confidenceScoreOverTime: [
        { year: 2024, confidence: 0.75, revenue: 0.12 },
        { year: 2025, confidence: 0.82, revenue: 1.5 },
        { year: 2026, confidence: 0.85, revenue: 5.2 },
        { year: 2027, confidence: 0.83, revenue: 15.8 },
        { year: 2028, confidence: 0.80, revenue: 38.5 }
      ],
      timeToPilotProduction: "2-3 months",
      scalabilityRoadmap: [
        { 
          phase: "MVP & Validation", 
          timeframe: "0-6 months", 
          focus: "Product-market fit, early adopters" 
        },
        { 
          phase: "Growth", 
          timeframe: "6-18 months", 
          focus: "Scale to 100+ customers, Series A" 
        },
        { 
          phase: "Expansion", 
          timeframe: "18-36 months", 
          focus: "Enterprise features, international" 
        }
      ],
      strengths: [
        "Strong technical founding team with domain expertise",
        "Clear product vision addressing real market pain points",
        "AI-first approach provides competitive advantage",
        "Low customer acquisition cost with viral potential",
        "Scalable SaaS model with healthy unit economics"
      ],
      challenges: [
        "Need stronger go-to-market strategy for enterprise",
        "Competitive market requires clear differentiation",
        "Customer retention metrics need improvement",
        "Regulatory compliance for data handling required",
        "Scaling team while maintaining culture is critical"
      ]
    };
  }

  static async analyzeStartup(inputText, companyName) {
    // Simulate AI processing
    const analysis = {
      dealNotes: this.generateDealNotes(companyName),
      riskAssessment: this.generateRiskAssessment(),
      competitors: this.generateCompetitorAnalysis(),
      funding: this.generateFundingAnalysis(),
      growth: this.generateGrowthProjections(),
      timestamp: new Date().toISOString(),
      processingComplete: true
    };

    // Add some randomization based on input
    if (inputText && inputText.toLowerCase().includes('ai')) {
      analysis.dealNotes.founderAnalysis.confidence += 0.05;
      analysis.funding.fundingLikelihood += 0.05;
    }

    if (inputText && inputText.toLowerCase().includes('revenue')) {
      analysis.dealNotes.traction.revenue = "$50K MRR";
      analysis.funding.fundingLikelihood += 0.1;
    }

    return analysis;
  }
}

// Routes
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    const analysisId = uuidv4();
    
    // Store file metadata (in production, you'd process the file)
    const fileInfo = {
      id: analysisId,
      originalName: req.file?.originalname || 'unknown',
      mimeType: req.file?.mimetype || 'application/octet-stream',
      size: req.file?.size || 0,
      uploadTime: new Date().toISOString()
    };

    // Simulate processing
    setTimeout(() => {
      console.log(`Processing file: ${fileInfo.originalName}`);
    }, 1000);

    res.json({ 
      success: true, 
      analysisId,
      message: "File uploaded successfully, analysis started" 
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

app.post('/api/analyze-text', async (req, res) => {
  try {
    const { text, companyName } = req.body;
    
    if (!text || text.trim().length < 10) {
      return res.status(400).json({ 
        success: false, 
        error: "Please provide more detailed information about your startup" 
      });
    }
    
    const analysisId = uuidv4();
    
    // Log the analysis request
    console.log(`Analyzing startup: ${companyName || 'Unnamed'}`);
    console.log(`Input length: ${text.length} characters`);
    
    res.json({
      success: true,
      analysisId,
      message: "Analysis started successfully",
      estimatedTime: "10-15 seconds"
    });
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

app.get('/api/analysis/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Simulate fetching stored analysis
    // In production, you'd retrieve from database
    const companyName = "TechStartup"; // Would come from stored data
    const inputText = "AI-powered B2B SaaS platform"; // Would come from stored data
    
    const analysis = await StartoscopeAnalyst.analyzeStartup(inputText, companyName);
    
    res.json({ 
      success: true, 
      data: analysis,
      analysisId: id 
    });
  } catch (error) {
    console.error('Fetch analysis error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

app.get('/api/benchmarks', (req, res) => {
  try {
    const benchmarks = {
      sectorAverages: {
        revenueGrowth: 0.20, // 20% MoM
        churnRate: 0.05, // 5% monthly
        cac: 500, // $500 CAC
        ltv: 5000, // $5000 LTV
        burnRate: 50000 // $50K monthly
      },
      peerComparison: [
        { metric: "Revenue Growth", ourValue: 0.25, peerAverage: 0.20, percentile: 75 },
        { metric: "Churn Rate", ourValue: 0.04, peerAverage: 0.05, percentile: 80 },
        { metric: "CAC", ourValue: 400, peerAverage: 500, percentile: 85 },
        { metric: "LTV:CAC Ratio", ourValue: 12.5, peerAverage: 10, percentile: 82 }
      ],
      industryInsights: {
        topPerformers: [
          "Companies with AI features grow 2x faster",
          "Mobile-first solutions have 30% lower churn",
          "Vertical SaaS has higher retention rates"
        ],
        trends: [
          "AI integration becoming table stakes",
          "PLG (Product-Led Growth) dominant strategy",
          "Increased focus on profitability over growth"
        ]
      }
    };

    res.json({ 
      success: true, 
      data: benchmarks 
    });
  } catch (error) {
    console.error('Benchmarks error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    service: 'Startoscope API',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    success: false, 
    error: 'Endpoint not found' 
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ 
    success: false, 
    error: 'Internal server error' 
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`
   Startoscope Server Running
   Port: ${PORT}
   URL: http://localhost:${PORT}
   Ready to analyze startups!
  `);
});

module.exports = app;