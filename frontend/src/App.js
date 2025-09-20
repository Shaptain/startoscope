// App.js - Updated with Authentication and Real Backend Integration
import React, { useState, useEffect } from 'react';
import { TrendingUp, Upload, FileText, Briefcase, Target, DollarSign, Zap, Brain, Diamond, BookOpen, Rocket, AlertTriangle, LogOut, User, Download, Save } from 'lucide-react';
import jsPDF from 'jspdf';
import Chatbot from './components/Chatbot';
import './App.css';

const API_BASE = 'http://localhost:3001/api';

function App() {
  const [currentPage, setCurrentPage] = useState('home');
  const [loading, setLoading] = useState(false);
  const [analysisData, setAnalysisData] = useState(null);
  const [journalIdeas, setJournalIdeas] = useState([]);
  const [modalOpen, setModalOpen] = useState(false);
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [isLogin, setIsLogin] = useState(true);
  const [currentIdea, setCurrentIdea] = useState({ title: '', description: '' });
  const [dragActive, setDragActive] = useState(false);
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [currency, setCurrency] = useState('INR'); // INR or USD
  const [exchangeRate, setExchangeRate] = useState(83);

  useEffect(() => {
    // Check if user is logged in
    if (token) {
      validateToken();
    }
    loadJournalFromLocal();
    fetchExchangeRate();
  }, [token]);

  // Validate token and get user info
  const validateToken = async () => {
    try {
      const response = await fetch(`${API_BASE}/auth/verify`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setUser(data.user);
        loadJournalFromServer();
      } else {
        // Token invalid, clear it
        localStorage.removeItem('token');
        setToken(null);
        setUser(null);
      }
    } catch (error) {
      console.error('Token validation error:', error);
    }
  };

  // Fetch exchange rate
  const fetchExchangeRate = async () => {
    try {
      const response = await fetch(`${API_BASE}/exchange-rate`);
      const data = await response.json();
      if (data.success) {
        setExchangeRate(data.rate);
      }
    } catch (error) {
      console.error('Exchange rate fetch error:', error);
    }
  };

  // Load journal from local storage (for non-logged in users)
  const loadJournalFromLocal = () => {
    const saved = localStorage.getItem('startoscopeIdeas');
    if (saved) {
      setJournalIdeas(JSON.parse(saved));
    }
  };

  // Load journal from server (for logged in users)
  const loadJournalFromServer = async () => {
    try {
      const response = await fetch(`${API_BASE}/journal`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setJournalIdeas(data.data);
      }
    } catch (error) {
      console.error('Journal fetch error:', error);
    }
  };

  // Handle login
  const handleLogin = async (email, password) => {
    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      
      const data = await response.json();
      
      if (data.success) {
        setToken(data.token);
        setUser(data.user);
        localStorage.setItem('token', data.token);
        setAuthModalOpen(false);
        loadJournalFromServer();
      } else {
        alert(data.error || 'Login failed');
      }
    } catch (error) {
      console.error('Login error:', error);
      alert('Login failed. Please try again.');
    }
  };

  // Handle signup
  const handleSignup = async (email, password, name) => {
    try {
      const response = await fetch(`${API_BASE}/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, name })
      });
      
      const data = await response.json();
      
      if (data.success) {
        setToken(data.token);
        setUser(data.user);
        localStorage.setItem('token', data.token);
        setAuthModalOpen(false);
      } else {
        alert(data.error || 'Signup failed');
      }
    } catch (error) {
      console.error('Signup error:', error);
      alert('Signup failed. Please try again.');
    }
  };

  // Handle logout
  const handleLogout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
    loadJournalFromLocal();
  };

  const showPage = (page) => {
    setCurrentPage(page);
    window.scrollTo(0, 0);
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const handleFileUpload = async (file) => {
    setLoading(true);
    const formData = new FormData();
    formData.append('file', file);
    
    const companyName = document.getElementById('companyName')?.value;
    if (companyName) {
      formData.append('companyName', companyName);
    }

    try {
      const headers = {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      
      const response = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers,
        body: formData
      });
      
      const result = await response.json();
      
      if (result.success) {
        setAnalysisData(result.data);
        setCurrentPage('report');
      } else {
        alert(result.error || 'Analysis failed');
      }
    } catch (error) {
      console.error('Upload failed:', error);
      alert('Upload failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const analyzeText = async () => {
    const companyName = document.getElementById('companyName').value;
    const ideaText = document.getElementById('ideaText').value;
    
    if (!ideaText.trim()) {
      alert('Please enter some text to analyze');
      return;
    }

    setLoading(true);
    try {
      const headers = { 'Content-Type': 'application/json' };
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      
      const response = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ text: ideaText, companyName })
      });
      
      const result = await response.json();
      
      if (result.success) {
        setAnalysisData(result.data);
        setCurrentPage('report');
      } else {
        alert(result.error || 'Analysis failed');
      }
    } catch (error) {
      console.error('Analysis failed:', error);
      alert('Analysis failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const loadSampleAnalysis = () => {
    document.getElementById('companyName').value = 'TechFlow India';
    document.getElementById('ideaText').value = 'We are building an AI-powered B2B SaaS platform that helps Indian enterprises automate their workflow processes. Our solution uses natural language processing to understand business documents and automatically route them through the appropriate approval chains. We already have 5 pilot customers including 2 Fortune 500 companies.';
    analyzeText();
  };

  const saveToJournal = async () => {
    if (!user) {
      setAuthModalOpen(true);
      return;
    }
    
    try {
      const response = await fetch(`${API_BASE}/journal/save`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ analysisId: analysisData.analysisId })
      });
      
      const result = await response.json();
      if (result.success) {
        alert('Analysis saved to journal!');
        loadJournalFromServer();
      }
    } catch (error) {
      console.error('Save to journal error:', error);
      alert('Failed to save to journal');
    }
  };

  const exportAsPDF = () => {
    const doc = new jsPDF();
    
    // Add title
    doc.setFontSize(20);
    doc.text(analysisData.companyName || 'Startup Analysis', 20, 20);
    
    // Add confidence score
    doc.setFontSize(14);
    doc.text(`Confidence Score: ${Math.round((analysisData.confidence || 0.75) * 100)}%`, 20, 35);
    
    // Add metrics
    doc.setFontSize(12);
    let yPos = 50;
    
    doc.text('Key Metrics:', 20, yPos);
    yPos += 10;
    doc.text(`• Funding Potential: ${currency === 'INR' ? analysisData.fundingPotentialINR : analysisData.fundingPotentialUSD}`, 25, yPos);
    yPos += 8;
    doc.text(`• Market Size: ${currency === 'INR' ? analysisData.marketSizeINR : analysisData.marketSizeUSD}`, 25, yPos);
    yPos += 8;
    doc.text(`• Growth Rate: ${analysisData.growthRate}`, 25, yPos);
    yPos += 8;
    doc.text(`• Product-Market Fit: ${analysisData.productMarketFit}`, 25, yPos);
    
    // Add strengths
    yPos += 15;
    doc.text('Strengths:', 20, yPos);
    yPos += 8;
    (analysisData.strengths || []).forEach(strength => {
      if (yPos > 270) {
        doc.addPage();
        yPos = 20;
      }
      const lines = doc.splitTextToSize(`• ${strength}`, 170);
      doc.text(lines, 25, yPos);
      yPos += lines.length * 5;
    });
    
    // Add challenges
    yPos += 10;
    if (yPos > 250) {
      doc.addPage();
      yPos = 20;
    }
    doc.text('Challenges:', 20, yPos);
    yPos += 8;
    (analysisData.challenges || []).forEach(challenge => {
      if (yPos > 270) {
        doc.addPage();
        yPos = 20;
      }
      const lines = doc.splitTextToSize(`• ${challenge}`, 170);
      doc.text(lines, 25, yPos);
      yPos += lines.length * 5;
    });
    
    // Save the PDF
    doc.save(`${analysisData.companyName || 'startup'}-analysis.pdf`);
  };

  const toggleCurrency = () => {
    setCurrency(currency === 'INR' ? 'USD' : 'INR');
  };

  return (
    <div className="app">
      {/* Add Chatbot Component */}
      <Chatbot />

      {/* Navigation */}
      <nav className="navbar">
        <div className="nav-container">
          <div className="logo">
            <svg className="growth-icon" viewBox="0 0 24 24">
              <polyline points="22 7 13.5 15.5 8.5 10.5 2 17"></polyline>
              <polyline points="15 7 22 7 22 14"></polyline>
            </svg>
            STARTOSCOPE
          </div>
          <div className="nav-links">
            <a className="nav-link" onClick={() => showPage('home')}>Home</a>
            <a className="nav-link" onClick={() => showPage('journal')}>Journal</a>
            <button className="analyze-btn" onClick={() => showPage('upload')}>
              Analyze Your Business
            </button>
            {user ? (
              <div className="user-menu">
                <span className="user-name">{user.name || user.email}</span>
                <button className="logout-btn" onClick={handleLogout}>
                  <LogOut size={16} />
                </button>
              </div>
            ) : (
              <button className="login-btn" onClick={() => setAuthModalOpen(true)}>
                <User size={16} /> Login
              </button>
            )}
          </div>
        </div>
      </nav>

      {/* Home Page */}
      {currentPage === 'home' && <HomePage showPage={showPage} />}

      {/* Journal Page */}
      {currentPage === 'journal' && (
        <JournalPage 
          ideas={journalIdeas}
          user={user}
          onLogin={() => setAuthModalOpen(true)}
        />
      )}

      {/* Upload Page */}
      {currentPage === 'upload' && (
        <UploadPage
          dragActive={dragActive}
          handleDrag={handleDrag}
          handleDrop={handleDrop}
          handleFileUpload={handleFileUpload}
          analyzeText={analyzeText}
          loadSampleAnalysis={loadSampleAnalysis}
        />
      )}

      {/* Report Page */}
      {currentPage === 'report' && analysisData && (
        <ReportPage
          data={analysisData}
          currency={currency}
          toggleCurrency={toggleCurrency}
          onNewAnalysis={() => showPage('upload')}
          onSaveToJournal={saveToJournal}
          onExportPDF={exportAsPDF}
          user={user}
        />
      )}

      {/* Loading Overlay */}
      {loading && <LoadingOverlay />}

      {/* Auth Modal */}
      {authModalOpen && (
        <AuthModal
          isLogin={isLogin}
          setIsLogin={setIsLogin}
          onClose={() => setAuthModalOpen(false)}
          onLogin={handleLogin}
          onSignup={handleSignup}
        />
      )}
    </div>
  );
}

// Component: Home Page
const HomePage = ({ showPage }) => (
  <div className="page-section active">
    <div className="hero">
      <div className="hero-bg"></div>
      <div className="hero-content">
        <h1 className="hero-title">
          Transform your <span className="highlight">shower thought</span><br/>
          to an investor-ready startup
        </h1>
        <p className="hero-subtitle">
          We turn your random 3am ideas into venture-backable businesses. 
          No MBA required, just vibes and AI magic ✨
        </p>
        <div className="cta-buttons">
          <button className="cta-primary" onClick={() => showPage('upload')}>
            Start Analysis
          </button>
          <button className="cta-secondary" onClick={() => showPage('journal')}>
            Save Ideas
          </button>
        </div>
      </div>
    </div>

    <div className="features">
      <h2 className="section-title">Why Startoscope Hits Different</h2>
      <div className="features-grid">
        <FeatureCard 
          icon={<Brain className="feature-icon-svg" />}
          title="Real AI Analysis"
          desc="Powered by advanced AI that actually understands your business context. We analyze PDFs, presentations, and raw text to generate actionable insights."
        />
        <FeatureCard 
          icon={<TrendingUp className="feature-icon-svg" />}
          title="Indian Market Focus"
          desc="Get analysis in INR with Indian market benchmarks. Toggle to USD for global perspective. Real exchange rates updated daily."
        />
        <FeatureCard 
          icon={<Diamond className="feature-icon-svg" />}
          title="Competitive Intelligence"
          desc="See real competitors with actual valuations and links. Understand your market position and differentiation opportunities."
        />
        <FeatureCard 
          icon={<BookOpen className="feature-icon-svg" />}
          title="Smart Journal"
          desc="Save your analyses to your personal journal. Track progress over time, compare different ideas, and build your startup portfolio."
        />
        <FeatureCard 
          icon={<Rocket className="feature-icon-svg" />}
          title="Export Ready Reports"
          desc="Download professional PDF reports or save to your journal. Perfect for investor meetings or team discussions."
        />
        <FeatureCard 
          icon={<Zap className="feature-icon-svg" />}
          title="No BS, Just Results"
          desc="Built by developers who get it. Clean interface, real data, actionable insights. Ship fast, iterate faster."
        />
      </div>
    </div>
  </div>
);

// Component: Journal Page
const JournalPage = ({ ideas, user, onLogin }) => (
  <div className="page-section active">
    <div className="journal-container">
      <div className="journal-header">
        <h2 className="section-title">Your Startup Ideas</h2>
        {!user && (
          <button className="login-prompt" onClick={onLogin}>
            Login to sync journal
          </button>
        )}
      </div>
      
      {ideas.length === 0 ? (
        <div className="empty-state">
          <p>No saved analyses yet. Start analyzing to build your journal!</p>
        </div>
      ) : (
        <div className="ideas-grid">
          {ideas.map((idea, index) => (
            <div key={index} className="idea-card">
              <div className="idea-score">
                {Math.round((idea.analysis?.confidence || 0.75) * 100)}%
              </div>
              <h3 className="idea-title">{idea.companyName || idea.analysis?.companyName}</h3>
              <div className="idea-date">
                {new Date(idea.createdAt).toLocaleDateString()}
              </div>
              <div className="idea-metrics">
                <div className="metric-pill">
                  {idea.analysis?.fundingPotentialINR || '₹2-5 Cr'}
                </div>
                <div className="metric-pill">
                  {idea.analysis?.growthRate || '25%'} growth
                </div>
              </div>
              <p className="idea-preview">
                {idea.analysis?.executiveSummary || idea.inputText?.substring(0, 150) || 'Analysis summary...'}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  </div>
);

// Component: Upload Page
const UploadPage = ({ dragActive, handleDrag, handleDrop, handleFileUpload, analyzeText, loadSampleAnalysis }) => (
  <div className="page-section active">
    <div className="upload-container">
      <h2 className="section-title">Drop Your Startup Materials</h2>
      
      <div 
        className={`upload-area ${dragActive ? 'drag-active' : ''}`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => document.getElementById('fileInput').click()}
      >
        <input 
          type="file" 
          id="fileInput" 
          style={{ display: 'none' }}
          onChange={(e) => e.target.files[0] && handleFileUpload(e.target.files[0])}
          accept=".pdf,.doc,.docx,.txt,.ppt,.pptx"
        />
        <Upload className="upload-icon" />
        <h3>Drop files here</h3>
        <p className="upload-subtitle">or click to browse</p>
        <p className="upload-info">Accepts: PDF, Word, PowerPoint, Text files</p>
      </div>

      <div className="text-input-container">
        <h3>Or paste your idea</h3>
        <input 
          type="text" 
          className="text-input" 
          id="companyName" 
          placeholder="Company name (optional - AI will generate if blank)"
        />
        <textarea 
          className="text-input" 
          id="ideaText" 
          placeholder="Describe your startup idea, paste your pitch, or just brain dump here..."
        />
        <button className="cta-primary full-width" onClick={analyzeText}>
          Analyze This
        </button>
      </div>

      <div className="sample-container">
        <button className="cta-secondary" onClick={loadSampleAnalysis}>
          Try Sample Analysis
        </button>
      </div>
    </div>
  </div>
);

// Component: Report Page
const ReportPage = ({ data, currency, toggleCurrency, onNewAnalysis, onSaveToJournal, onExportPDF, user }) => {
  const confidence = data.confidence || 0.75;
  
  return (
    <div className="page-section active">
      <div className="report-container">
        <div className="report-header">
          <h1>{data.companyName || 'Your Startup'}</h1>
          <div className="confidence-score">{Math.round(confidence * 100)}% Confidence Score</div>
          <p className="report-date">Analysis completed on {new Date().toLocaleDateString()}</p>
          
          <div className="currency-toggle">
            <button 
              className={`currency-btn ${currency === 'INR' ? 'active' : ''}`}
              onClick={() => currency === 'USD' && toggleCurrency()}
            >
              ₹ INR
            </button>
            <button 
              className={`currency-btn ${currency === 'USD' ? 'active' : ''}`}
              onClick={() => currency === 'INR' && toggleCurrency()}
            >
              $ USD
            </button>
          </div>
        </div>

        <div className="report-grid">
          <MetricCard 
            icon={<DollarSign />} 
            title="Funding Potential"
            value={currency === 'INR' ? data.fundingPotentialINR : data.fundingPotentialUSD}
            label="Recommended round size"
          />
          <MetricCard 
            icon={<TrendingUp />}
            title="Market Size"
            value={currency === 'INR' ? data.marketSizeINR : data.marketSizeUSD}
            label="Total addressable market"
          />
          <MetricCard 
            icon={<Zap />}
            title="Growth Rate"
            value={data.growthRate}
            label="Expected annual growth"
          />
          <MetricCard 
            icon={<Target />}
            title="Product-Market Fit"
            value={data.productMarketFit}
            label="Based on market analysis"
          />
        </div>

        {data.competitors && data.competitors.length > 0 && (
          <div className="competitors-section">
            <h2>Similar Startups</h2>
            {data.competitors.map((comp, idx) => (
              <div key={idx} className="competitor-item">
                <div>
                  <div className="competitor-name">{comp.name}</div>
                  <div className="competitor-desc">{comp.description}</div>
                </div>
                {comp.url && (
                  <a href={comp.url} target="_blank" rel="noopener noreferrer" className="competitor-link">
                    Visit →
                  </a>
                )}
              </div>
            ))}
          </div>
        )}

        <div className="strengths-challenges">
          <div className="section-box strengths">
            <h3>💪 Strengths</h3>
            {(data.strengths || []).map((strength, idx) => (
              <div key={idx} className="list-item">{strength}</div>
            ))}
          </div>
          <div className="section-box challenges">
            <h3>🎯 Challenges to Address</h3>
            {(data.challenges || []).map((challenge, idx) => (
              <div key={idx} className="list-item">{challenge}</div>
            ))}
          </div>
        </div>

        {data.executiveSummary && (
          <div className="executive-summary">
            <h3>Executive Summary</h3>
            <p>{data.executiveSummary}</p>
          </div>
        )}

        <div className="report-actions">
          <button className="cta-primary" onClick={onExportPDF}>
            <Download size={16} /> Export PDF
          </button>
          {user ? (
            <button className="cta-secondary" onClick={onSaveToJournal}>
              <Save size={16} /> Save to Journal
            </button>
          ) : (
            <button className="cta-secondary" onClick={onSaveToJournal}>
              <User size={16} /> Login to Save
            </button>
          )}
          <button className="cta-secondary" onClick={onNewAnalysis}>
            New Analysis
          </button>
        </div>
      </div>
    </div>
  );
};

// Component: Auth Modal
const AuthModal = ({ isLogin, setIsLogin, onClose, onLogin, onSignup }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  
  const handleSubmit = (e) => {
    e.preventDefault();
    if (isLogin) {
      onLogin(email, password);
    } else {
      onSignup(email, password, name);
    }
  };
  
  return (
    <div className="modal active">
      <div className="modal-content auth-modal">
        <span className="modal-close" onClick={onClose}>&times;</span>
        <h2>{isLogin ? 'Login' : 'Sign Up'}</h2>
        
        <form onSubmit={handleSubmit}>
          {!isLogin && (
            <input 
              type="text" 
              className="text-input" 
              placeholder="Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          )}
          <input 
            type="email" 
            className="text-input" 
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <input 
            type="password" 
            className="text-input" 
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          
          <button type="submit" className="cta-primary full-width">
            {isLogin ? 'Login' : 'Sign Up'}
          </button>
        </form>
        
        <p className="auth-switch">
          {isLogin ? "Don't have an account? " : "Already have an account? "}
          <a onClick={() => setIsLogin(!isLogin)}>
            {isLogin ? 'Sign Up' : 'Login'}
          </a>
        </p>
      </div>
    </div>
  );
};

// Helper Components
const FeatureCard = ({ icon, title, desc }) => (
  <div className="feature-card">
    <div className="feature-icon">{icon}</div>
    <h3 className="feature-title">{title}</h3>
    <p className="feature-desc">{desc}</p>
  </div>
);

const MetricCard = ({ icon, title, value, label }) => (
  <div className="report-card">
    <div className="report-card-title">
      {icon} {title}
    </div>
    <div className="metric-value">{value}</div>
    <div className="metric-label">{label}</div>
  </div>
);

const LoadingOverlay = () => (
  <div className="loading-overlay">
    <svg className="growth-loader" viewBox="0 0 100 100">
      <polyline 
        points="10,70 30,50 50,60 70,20 90,40" 
        fill="none" 
        strokeWidth="3" 
        strokeLinecap="round"
      />
    </svg>
    <div className="loading-text">AI is analyzing your startup...</div>
    <div className="loading-steps">
      <div className="loading-step">✓ Processing your content</div>
      <div className="loading-step">✓ Analyzing market dynamics</div>
      <div className="loading-step">✓ Finding competitors</div>
      <div className="loading-step">✓ Generating insights</div>
    </div>
  </div>
);

export default App;