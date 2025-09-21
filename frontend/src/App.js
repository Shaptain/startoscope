// App.js - Clean Authentication Flow with Professional UI
import React, { useState, useEffect, useRef } from 'react';
import { 
  TrendingUp, Upload, FileText, Briefcase, Target, DollarSign, Zap, Brain, 
  Diamond, BookOpen, Rocket, AlertTriangle, LogOut, User, Download, Save, 
  ChevronDown, Settings, HelpCircle, Shield, Bell 
} from 'lucide-react';
import jsPDF from 'jspdf';
import Chatbot from './components/Chatbot';
import './App.css';

const API_BASE = 'http://localhost:3001/api';

// Enhanced Auth Service with automatic token refresh
class AuthService {
  static TOKEN_KEY = 'startoscope_token';
  static REFRESH_TOKEN_KEY = 'startoscope_refresh_token';
  static USER_KEY = 'startoscope_user';

  static setTokens(accessToken, refreshToken) {
    localStorage.setItem(this.TOKEN_KEY, accessToken);
    if (refreshToken) {
      localStorage.setItem(this.REFRESH_TOKEN_KEY, refreshToken);
    }
  }

  static setUser(user) {
    localStorage.setItem(this.USER_KEY, JSON.stringify(user));
  }

  static getToken() {
    return localStorage.getItem(this.TOKEN_KEY);
  }

  static getRefreshToken() {
    return localStorage.getItem(this.REFRESH_TOKEN_KEY);
  }

  static getUser() {
    const userStr = localStorage.getItem(this.USER_KEY);
    return userStr ? JSON.parse(userStr) : null;
  }

  static clearAll() {
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.REFRESH_TOKEN_KEY);
    localStorage.removeItem(this.USER_KEY);
  }

  static async verifyToken() {
    const token = this.getToken();
    if (!token) return null;

    try {
      const response = await fetch(`${API_BASE}/auth/verify`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        const data = await response.json();
        return data.user;
      } else if (response.status === 401) {
        // Try to refresh token
        return await this.refreshTokens();
      }
    } catch (error) {
      console.error('Token verification error:', error);
    }

    return null;
  }

  static async refreshTokens() {
    const refreshToken = this.getRefreshToken();
    if (!refreshToken) return null;

    try {
      const response = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken })
      });

      if (response.ok) {
        const data = await response.json();
        this.setTokens(data.token, data.refreshToken);
        
        // Get user info with new token
        const user = await this.verifyToken();
        if (user) {
          this.setUser(user);
          return user;
        }
      }
    } catch (error) {
      console.error('Token refresh error:', error);
    }

    // If refresh fails, clear everything
    this.clearAll();
    return null;
  }

  static async login(email, password) {
    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      
      const data = await response.json();
      
      if (data.success) {
        this.setTokens(data.token, data.refreshToken);
        this.setUser(data.user);
        return { success: true, user: data.user };
      } else {
        return { success: false, error: data.error || 'Login failed' };
      }
    } catch (error) {
      console.error('Login error:', error);
      return { success: false, error: 'Network error. Please try again.' };
    }
  }

  static async signup(email, password, name) {
    try {
      const response = await fetch(`${API_BASE}/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, name })
      });
      
      const data = await response.json();
      
      if (data.success) {
        this.setTokens(data.token, data.refreshToken);
        this.setUser(data.user);
        return { success: true, user: data.user };
      } else {
        return { success: false, error: data.error || 'Signup failed' };
      }
    } catch (error) {
      console.error('Signup error:', error);
      return { success: false, error: 'Network error. Please try again.' };
    }
  }

  static async logout() {
    const token = this.getToken();
    
    if (token) {
      try {
        await fetch(`${API_BASE}/auth/logout`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}` }
        });
      } catch (error) {
        console.error('Logout API error:', error);
      }
    }
    
    this.clearAll();
  }

  // Helper to make authenticated requests
  static async makeAuthenticatedRequest(url, options = {}) {
    const token = this.getToken();
    
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };
    
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(url, {
      ...options,
      headers
    });

    // If unauthorized, try to refresh token
    if (response.status === 401 && token) {
      const refreshedUser = await this.refreshTokens();
      if (refreshedUser) {
        // Retry with new token
        headers['Authorization'] = `Bearer ${this.getToken()}`;
        return await fetch(url, {
          ...options,
          headers
        });
      }
    }

    return response;
  }
}

function App() {
  // Core state
  const [currentPage, setCurrentPage] = useState('home');
  const [loading, setLoading] = useState(false);
  const [analysisData, setAnalysisData] = useState(null);
  const [journalIdeas, setJournalIdeas] = useState([]);
  
  // Auth state
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [isLogin, setIsLogin] = useState(true);
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  
  // UI state
  const [dragActive, setDragActive] = useState(false);
  const [currency, setCurrency] = useState('INR');
  const [exchangeRate, setExchangeRate] = useState(83);
  const [profileDropdownOpen, setProfileDropdownOpen] = useState(false);
  const [notifications, setNotifications] = useState([]);

  // Refs
  const dropdownRef = useRef(null);

  // Initialize app
  useEffect(() => {
    initializeAuth();
    fetchExchangeRate();
    
    // Handle clicks outside dropdown
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setProfileDropdownOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const initializeAuth = async () => {
    setAuthLoading(true);
    
    try {
      // Try to get user from storage first
      const storedUser = AuthService.getUser();
      
      if (storedUser) {
        // Verify token is still valid
        const verifiedUser = await AuthService.verifyToken();
        
        if (verifiedUser) {
          setUser(verifiedUser);
          await loadJournalFromServer();
          showNotification('Welcome back!', 'success');
        } else {
          // Token invalid, fallback to local storage
          loadJournalFromLocal();
        }
      } else {
        loadJournalFromLocal();
      }
    } catch (error) {
      console.error('Auth initialization error:', error);
      loadJournalFromLocal();
    } finally {
      setAuthLoading(false);
    }
  };

  const fetchExchangeRate = async () => {
    try {
      const response = await fetch(`${API_BASE}/exchange-rate`);
      if (response.ok) {
        const data = await response.json();
        if (data.success) {
          setExchangeRate(data.rate);
        }
      }
    } catch (error) {
      console.error('Exchange rate fetch error:', error);
    }
  };

  const loadJournalFromLocal = () => {
    try {
      const saved = localStorage.getItem('startoscopeIdeas');
      if (saved) {
        setJournalIdeas(JSON.parse(saved));
      }
    } catch (error) {
      console.error('Error loading local journal:', error);
    }
  };

  const loadJournalFromServer = async () => {
    if (!user) return;
    
    try {
      const response = await AuthService.makeAuthenticatedRequest(`${API_BASE}/journal`);
      
      if (response.ok) {
        const data = await response.json();
        if (data.success) {
          setJournalIdeas(data.data);
        }
      } else if (response.status === 401) {
        // Token expired, handle logout
        await handleLogout();
      }
    } catch (error) {
      console.error('Journal fetch error:', error);
      showNotification('Failed to load journal', 'error');
    }
  };

  const showNotification = (message, type = 'info') => {
    const id = Date.now();
    setNotifications(prev => [...prev, { id, message, type }]);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }, 5000);
  };

  const handleAuth = async (email, password, name = null) => {
    setLoading(true);
    
    try {
      const result = isLogin 
        ? await AuthService.login(email, password)
        : await AuthService.signup(email, password, name);
      
      if (result.success) {
        setUser(result.user);
        setAuthModalOpen(false);
        setProfileDropdownOpen(false);
        
        // Load journal for authenticated user
        await loadJournalFromServer();
        
        showNotification(
          `${isLogin ? 'Login' : 'Account creation'} successful! Welcome${result.user.name ? `, ${result.user.name}` : ''}!`,
          'success'
        );
        
      } else {
        showNotification(result.error, 'error');
      }
    } catch (error) {
      console.error('Auth error:', error);
      showNotification('Authentication failed. Please try again.', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await AuthService.logout();
      setUser(null);
      setProfileDropdownOpen(false);
      setJournalIdeas([]);
      
      // Load local journal data
      loadJournalFromLocal();
      
      // Redirect to home if on protected pages
      if (currentPage === 'journal') {
        setCurrentPage('home');
      }
      
      showNotification('Logged out successfully', 'success');
    } catch (error) {
      console.error('Logout error:', error);
      showNotification('Logout failed', 'error');
    }
  };

  const showPage = (page) => {
    setCurrentPage(page);
    setProfileDropdownOpen(false);
    window.scrollTo(0, 0);
  };

  const toggleProfileDropdown = () => {
    setProfileDropdownOpen(!profileDropdownOpen);
  };

  // File handling
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
      const response = await AuthService.makeAuthenticatedRequest(`${API_BASE}/analyze`, {
        method: 'POST',
        body: formData,
        headers: {} // Don't set Content-Type for FormData
      });
      
      if (response.ok) {
        const result = await response.json();
        if (result.success) {
          setAnalysisData(result.data);
          setCurrentPage('report');
          showNotification('Analysis completed successfully!', 'success');
        } else {
          showNotification(result.error || 'Analysis failed', 'error');
        }
      } else {
        const result = await response.json();
        showNotification(result.error || 'Upload failed', 'error');
      }
    } catch (error) {
      console.error('Upload failed:', error);
      showNotification('Upload failed. Please try again.', 'error');
    } finally {
      setLoading(false);
    }
  };

  const analyzeText = async () => {
    const companyName = document.getElementById('companyName')?.value;
    const ideaText = document.getElementById('ideaText')?.value;
    
    if (!ideaText?.trim()) {
      showNotification('Please enter some text to analyze', 'error');
      return;
    }

    setLoading(true);
    try {
      const response = await AuthService.makeAuthenticatedRequest(`${API_BASE}/analyze`, {
        method: 'POST',
        body: JSON.stringify({ text: ideaText, companyName })
      });
      
      if (response.ok) {
        const result = await response.json();
        if (result.success) {
          setAnalysisData(result.data);
          setCurrentPage('report');
          showNotification('Analysis completed successfully!', 'success');
        } else {
          showNotification(result.error || 'Analysis failed', 'error');
        }
      } else {
        const result = await response.json();
        showNotification(result.error || 'Analysis failed', 'error');
      }
    } catch (error) {
      console.error('Analysis failed:', error);
      showNotification('Analysis failed. Please try again.', 'error');
    } finally {
      setLoading(false);
    }
  };

  const loadSampleAnalysis = () => {
    const companyNameField = document.getElementById('companyName');
    const ideaTextField = document.getElementById('ideaText');
    
    if (companyNameField) companyNameField.value = 'TechFlow India';
    if (ideaTextField) {
      ideaTextField.value = 'We are building an AI-powered B2B SaaS platform that helps Indian enterprises automate their workflow processes. Our solution uses natural language processing to understand business documents and automatically route them through the appropriate approval chains. We already have 5 pilot customers including 2 Fortune 500 companies.';
    }
    
    analyzeText();
  };

  const saveToJournal = async () => {
    if (!user) {
      setAuthModalOpen(true);
      showNotification('Please login to save to journal', 'error');
      return;
    }
    
    if (!analysisData?.analysisId) {
      showNotification('Cannot save analysis - missing ID', 'error');
      return;
    }
    
    try {
      const response = await AuthService.makeAuthenticatedRequest(`${API_BASE}/journal/save`, {
        method: 'POST',
        body: JSON.stringify({ analysisId: analysisData.analysisId })
      });
      
      if (response.ok) {
        const result = await response.json();
        if (result.success) {
          showNotification('Analysis saved to journal!', 'success');
          await loadJournalFromServer();
        } else {
          showNotification(result.error || 'Failed to save to journal', 'error');
        }
      } else if (response.status === 401) {
        await handleLogout();
        showNotification('Session expired. Please login again.', 'error');
      } else {
        showNotification('Failed to save to journal', 'error');
      }
    } catch (error) {
      console.error('Save to journal error:', error);
      showNotification('Failed to save to journal', 'error');
    }
  };

  const exportAsPDF = () => {
    if (!analysisData) return;
    
    try {
      const doc = new jsPDF();
      
      doc.setFontSize(20);
      doc.text(analysisData.companyName || 'Startup Analysis', 20, 20);
      
      doc.setFontSize(14);
      doc.text(`Confidence Score: ${Math.round((analysisData.confidence || 0.75) * 100)}%`, 20, 35);
      
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
      
      doc.save(`${analysisData.companyName || 'startup'}-analysis.pdf`);
      showNotification('PDF exported successfully!', 'success');
    } catch (error) {
      console.error('PDF export error:', error);
      showNotification('Failed to export PDF', 'error');
    }
  };

  const toggleCurrency = () => {
    setCurrency(currency === 'INR' ? 'USD' : 'INR');
  };

  // Show loading spinner during auth initialization
  if (authLoading) {
    return (
      <div className="app">
        <div className="auth-loading">
          <div className="loading-spinner large"></div>
          <p>Initializing...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      <Chatbot />

      {/* Notification System */}
      <NotificationSystem notifications={notifications} />

      {/* Enhanced Navigation */}
      <nav className="navbar">
        <div className="nav-container">
          <div className="logo" onClick={() => showPage('home')}>
            <svg className="growth-icon" viewBox="0 0 24 24">
              <polyline points="22 7 13.5 15.5 8.5 10.5 2 17"></polyline>
              <polyline points="15 7 22 7 22 14"></polyline>
            </svg>
            STARTOSCOPE
          </div>
          
          <div className="nav-links">
            <a className="nav-link" onClick={() => showPage('home')}>
              Home
            </a>
            
            <button className="analyze-btn" onClick={() => showPage('upload')}>
              <Rocket size={18} />
              Analyze Your Business
            </button>
            
            {user ? (
              <div className="profile-dropdown" ref={dropdownRef}>
                <button 
                  className="profile-trigger"
                  onClick={toggleProfileDropdown}
                  aria-expanded={profileDropdownOpen}
                >
                  <div className="profile-avatar">
                    {user.name ? user.name.charAt(0).toUpperCase() : user.email.charAt(0).toUpperCase()}
                  </div>
                  <span className="profile-name">{user.name || user.email.split('@')[0]}</span>
                  <ChevronDown 
                    size={16} 
                    className={`dropdown-icon ${profileDropdownOpen ? 'open' : ''}`} 
                  />
                </button>
                
                {profileDropdownOpen && (
                  <div className="profile-menu">
                    <div className="profile-info">
                      <div className="profile-avatar large">
                        {user.name ? user.name.charAt(0).toUpperCase() : user.email.charAt(0).toUpperCase()}
                      </div>
                      <div className="profile-details">
                        <div className="profile-display-name">{user.name || 'User'}</div>
                        <div className="profile-email">{user.email}</div>
                      </div>
                    </div>
                    
                    <div className="profile-menu-divider"></div>
                    
                    <button 
                      className="profile-menu-item"
                      onClick={() => showPage('journal')}
                    >
                      <BookOpen size={16} />
                      <span>Your Journal</span>
                    </button>
                    
                    <button className="profile-menu-item" disabled>
                      <Settings size={16} />
                      <span>Settings</span>
                      <span className="coming-soon">Soon</span>
                    </button>
                    
                    <button className="profile-menu-item" disabled>
                      <HelpCircle size={16} />
                      <span>Help & Support</span>
                    </button>
                    
                    <div className="profile-menu-divider"></div>
                    
                    <button 
                      className="profile-menu-item logout"
                      onClick={handleLogout}
                    >
                      <LogOut size={16} />
                      <span>Logout</span>
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <div className="auth-buttons">
                <button 
                  className="auth-btn login-btn" 
                  onClick={() => {
                    setIsLogin(true);
                    setAuthModalOpen(true);
                  }}
                >
                  <User size={16} />
                  Login
                </button>
                <button 
                  className="auth-btn signup-btn" 
                  onClick={() => {
                    setIsLogin(false);
                    setAuthModalOpen(true);
                  }}
                >
                  <Shield size={16} />
                  Sign Up
                </button>
              </div>
            )}
          </div>
        </div>
      </nav>

      {/* Page Content */}
      <main className="main-content">
        {currentPage === 'home' && <HomePage showPage={showPage} />}
        {currentPage === 'journal' && (
          <JournalPage 
            ideas={journalIdeas}
            user={user}
            onLogin={() => {
              setIsLogin(true);
              setAuthModalOpen(true);
            }}
          />
        )}
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
      </main>

      {/* Loading Overlay */}
      {loading && <LoadingOverlay />}

      {/* Enhanced Auth Modal */}
      {authModalOpen && (
        <AuthModal
          isLogin={isLogin}
          setIsLogin={setIsLogin}
          onClose={() => setAuthModalOpen(false)}
          onAuth={handleAuth}
          loading={loading}
        />
      )}
    </div>
  );
}

// Enhanced Auth Modal Component
const AuthModal = ({ isLogin, setIsLogin, onClose, onAuth, loading }) => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    name: ''
  });
  const [formErrors, setFormErrors] = useState({});
  const [showPassword, setShowPassword] = useState(false);

  const validateForm = () => {
    const errors = {};
    
    if (!formData.email) {
      errors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      errors.email = 'Please enter a valid email address';
    }
    
    if (!formData.password) {
      errors.password = 'Password is required';
    } else if (formData.password.length < 6) {
      errors.password = 'Password must be at least 6 characters long';
    }
    
    if (!isLogin && !formData.name?.trim()) {
      errors.name = 'Name is required for signup';
    }
    
    setFormErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    
    // Clear error for this field when user starts typing
    if (formErrors[name]) {
      setFormErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    
    if (!validateForm()) return;
    
    if (isLogin) {
      onAuth(formData.email, formData.password);
    } else {
      onAuth(formData.email, formData.password, formData.name);
    }
  };

  const resetForm = () => {
    setFormData({ email: '', password: '', name: '' });
    setFormErrors({});
  };

  const switchMode = () => {
    setIsLogin(!isLogin);
    resetForm();
  };

  // Handle escape key
  const handleKeyDown = (e) => {
    if (e.key === 'Escape' && !loading) {
      onClose();
    }
  };

  return (
    <div className="modal-overlay" onKeyDown={handleKeyDown}>
      <div className="modal-content auth-modal">
        <button 
          className="modal-close" 
          onClick={onClose} 
          disabled={loading}
          aria-label="Close"
        >
          &times;
        </button>
        
        <div className="auth-modal-header">
          <h2>{isLogin ? 'Welcome Back' : 'Create Your Account'}</h2>
          <p>
            {isLogin 
              ? 'Sign in to access your startup journal and saved analyses' 
              : 'Join thousands of entrepreneurs using Startoscope to validate their ideas'
            }
          </p>
        </div>
        
        <form onSubmit={handleSubmit} className="auth-form" noValidate>
          {!isLogin && (
            <div className="form-group">
              <label htmlFor="name" className="form-label">Full Name</label>
              <input 
                type="text" 
                id="name"
                name="name"
                className={`form-input ${formErrors.name ? 'error' : ''}`}
                placeholder="Enter your full name"
                value={formData.name}
                onChange={handleChange}
                disabled={loading}
                autoComplete="name"
              />
              {formErrors.name && (
                <span className="form-error" role="alert">{formErrors.name}</span>
              )}
            </div>
          )}
          
          <div className="form-group">
            <label htmlFor="email" className="form-label">Email Address</label>
            <input 
              type="email" 
              id="email"
              name="email"
              className={`form-input ${formErrors.email ? 'error' : ''}`}
              placeholder="Enter your email address"
              value={formData.email}
              onChange={handleChange}
              disabled={loading}
              autoComplete="email"
            />
            {formErrors.email && (
              <span className="form-error" role="alert">{formErrors.email}</span>
            )}
          </div>
          
          <div className="form-group">
            <label htmlFor="password" className="form-label">Password</label>
            <div className="password-input-wrapper">
              <input 
                type={showPassword ? "text" : "password"}
                id="password"
                name="password"
                className={`form-input ${formErrors.password ? 'error' : ''}`}
                placeholder="Enter your password"
                value={formData.password}
                onChange={handleChange}
                disabled={loading}
                autoComplete={isLogin ? "current-password" : "new-password"}
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowPassword(!showPassword)}
                disabled={loading}
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? '🙈' : '👁️'}
              </button>
            </div>
            {formErrors.password && (
              <span className="form-error" role="alert">{formErrors.password}</span>
            )}
          </div>
          
          <button 
            type="submit" 
            className="auth-submit-btn" 
            disabled={loading}
          >
            {loading ? (
              <span className="loading-spinner small"></span>
            ) : (
              isLogin ? 'Sign In' : 'Create Account'
            )}
          </button>
        </form>
        
        <div className="auth-switch">
          <span>
            {isLogin ? "Don't have an account? " : "Already have an account? "}
            <button 
              type="button" 
              className="auth-switch-btn" 
              onClick={switchMode}
              disabled={loading}
            >
              {isLogin ? 'Sign up' : 'Sign in'}
            </button>
          </span>
        </div>
      </div>
    </div>
  );
};

// Notification System Component
const NotificationSystem = ({ notifications }) => {
  if (!notifications.length) return null;

  return (
    <div className="notification-container">
      {notifications.map(notification => (
        <div 
          key={notification.id}
          className={`notification ${notification.type}`}
        >
          {notification.type === 'success' && <span className="notification-icon">✓</span>}
          {notification.type === 'error' && <span className="notification-icon">⚠</span>}
          {notification.type === 'info' && <span className="notification-icon">ℹ</span>}
          <span className="notification-message">{notification.message}</span>
        </div>
      ))}
    </div>
  );
};

// Loading Overlay Component
const LoadingOverlay = () => (
  <div className="loading-overlay">
    <div className="loading-content">
      <div className="loading-spinner large"></div>
      <p>Processing your request...</p>
    </div>
  </div>
);

// Feature Card Component
const FeatureCard = ({ icon, title, desc }) => (
  <div className="feature-card">
    <div className="feature-icon">
      {icon}
    </div>
    <h3 className="feature-title">{title}</h3>
    <p className="feature-desc">{desc}</p>
  </div>
);

// Page Components (keeping existing implementations)
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

const JournalPage = ({ ideas, user, onLogin }) => (
  <div className="page-section active">
    <div className="journal-container">
      <div className="journal-header">
        <h2 className="section-title">Your Startup Ideas</h2>
        {!user && (
          <button className="login-prompt" onClick={onLogin}>
            <User size={18} />
            Login to sync journal
          </button>
        )}
      </div>
      
      {ideas.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">
            <BookOpen size={48} />
          </div>
          <h3>No saved analyses yet</h3>
          <p>Start analyzing your startup ideas to build your journal!</p>
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
          rows="6"
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

const ReportPage = ({ data, currency, toggleCurrency, onNewAnalysis, onSaveToJournal, onExportPDF, user }) => (
  <div className="page-section active">
    <div className="report-container">
      <div className="report-header">
        <h2 className="company-name">{data.companyName}</h2>
        <div className="confidence-badge">
          {Math.round((data.confidence || 0.75) * 100)}% Confidence
        </div>
      </div>

      <div className="report-actions">
        <button className="action-btn" onClick={onNewAnalysis}>
          <Rocket size={16} />
          New Analysis
        </button>
        {user && (
          <button className="action-btn" onClick={onSaveToJournal}>
            <Save size={16} />
            Save to Journal
          </button>
        )}
        <button className="action-btn" onClick={onExportPDF}>
          <Download size={16} />
          Export PDF
        </button>
        <button className="currency-toggle" onClick={toggleCurrency}>
          {currency}
        </button>
      </div>

      <div className="metrics-grid">
        <div className="metric-card">
          <DollarSign className="metric-icon" />
          <h3>Funding Potential</h3>
          <p className="metric-value">
            {currency === 'INR' ? data.fundingPotentialINR : data.fundingPotentialUSD}
          </p>
        </div>
        
        <div className="metric-card">
          <Target className="metric-icon" />
          <h3>Market Size</h3>
          <p className="metric-value">
            {currency === 'INR' ? data.marketSizeINR : data.marketSizeUSD}
          </p>
        </div>
        
        <div className="metric-card">
          <TrendingUp className="metric-icon" />
          <h3>Growth Rate</h3>
          <p className="metric-value">{data.growthRate}</p>
        </div>
        
        <div className="metric-card">
          <Briefcase className="metric-icon" />
          <h3>Product-Market Fit</h3>
          <p className="metric-value">{data.productMarketFit}</p>
        </div>
      </div>

      <div className="analysis-sections">
        <div className="analysis-section">
          <h3>Strengths</h3>
          <ul>
            {(data.strengths || []).map((strength, index) => (
              <li key={index}>{strength}</li>
            ))}
          </ul>
        </div>

        <div className="analysis-section">
          <h3>Challenges</h3>
          <ul>
            {(data.challenges || []).map((challenge, index) => (
              <li key={index}>{challenge}</li>
            ))}
          </ul>
        </div>

        <div className="analysis-section">
          <h3>Key Competitors</h3>
          <div className="competitors-list">
            {(data.competitors || []).map((competitor, index) => (
              <div key={index} className="competitor-card">
                <h4>{competitor.name}</h4>
                <p>{competitor.description}</p>
                {competitor.url && (
                  <a href={competitor.url} target="_blank" rel="noopener noreferrer">
                    Visit Website
                  </a>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="analysis-section">
          <h3>Executive Summary</h3>
          <p>{data.executiveSummary}</p>
        </div>
      </div>
    </div>
  </div>
);

export default App;