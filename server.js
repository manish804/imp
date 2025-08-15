import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables - prefer .env.local over .env
const envLocalPath = path.join(__dirname, '.env.local');
const envPath = path.join(__dirname, '.env');

if (fs.existsSync(envLocalPath)) {
  dotenv.config({ path: envLocalPath });
  console.log('Loaded configuration from .env.local');
} else if (fs.existsSync(envPath)) {
  dotenv.config({ path: envPath });
  console.log('Loaded configuration from .env');
} else {
  dotenv.config();
  console.log('Using default environment variables');
}

const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true
}));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Session storage (in production, use Redis or a database)
const sessions = new Map();
const SESSION_DURATION = 60 * 60 * 1000; // 1 hour

// Cleanup expired sessions
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions.entries()) {
    if (now > session.expiresAt) {
      sessions.delete(token);
    }
  }
}, 5 * 60 * 1000); // Clean every 5 minutes

// Helper to extract API keys from environment
function extractKeys(baseKeyName) {
  const keys = new Set();
  const envVarMap = {
    'PERPLEXITY_API_KEY': 'PERPLEXITY_API_KEY',
    'GOOGLE_API_KEY': 'GOOGLE_API_KEY',
    'GROQ_API_KEY': 'GROQ_API_KEY',
    'OPENAI_API_KEY': 'OPENAI_API_KEY',
    'OPENROUTER_API_KEY': 'OPENROUTER_API_KEY',
    'GITHUB_TOKEN': 'GITHUB_TOKEN',
    'COHERE_API_KEY': 'COHERE_API_KEY',
  };
  
  const base = envVarMap[baseKeyName] || baseKeyName;
  
  // Direct key
  if (process.env[base]) {
    keys.add(process.env[base]);
  }
  
  // Numbered variants - check up to 20 keys per service
  for (let i = 1; i <= 20; i++) {
    // Try both KEY1 and KEY_1 formats
    const key1 = process.env[`${base}${i}`];
    const key2 = process.env[`${base}_${i}`];
    
    if (key1 && key1.trim()) keys.add(key1.trim());
    if (key2 && key2.trim()) keys.add(key2.trim());
  }
  
  // Debug logging for troubleshooting
  if (keys.size === 0) {
    console.log(`No keys found for ${baseKeyName}. Checked: ${base}, ${base}1-20, ${base}_1-20`);
  }
  
  return Array.from(keys);
}

// Middleware to verify session token
function authenticateSession(req, res, next) {
  const token = req.headers['x-session-token'];
  
  if (!token) {
    return res.status(401).json({ error: 'No session token provided' });
  }
  
  const session = sessions.get(token);
  
  if (!session || Date.now() > session.expiresAt) {
    sessions.delete(token);
    return res.status(401).json({ error: 'Session expired or invalid' });
  }
  
  // Refresh session
  session.expiresAt = Date.now() + SESSION_DURATION;
  req.session = session;
  next();
}

// Initialize session - client calls this first
app.post('/api/session/init', (req, res) => {
  const token = uuidv4();
  const session = {
    id: token,
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_DURATION,
    keyIndices: {
      perplexity: 0,
      gemini: 0,
      groq: 0,
      openai: 0,
      openrouter: 0,
      github: 0,
      cohere: 0
    }
  };
  
  sessions.set(token, session);
  
  // Get actual key counts for each service
  const groqKeys = extractKeys('GROQ_API_KEY');
  const geminiKeys = extractKeys('GOOGLE_API_KEY');
  const perplexityKeys = extractKeys('PERPLEXITY_API_KEY');
  const openaiKeys = extractKeys('OPENAI_API_KEY');
  const openrouterKeys = extractKeys('OPENROUTER_API_KEY');
  const githubKeys = extractKeys('GITHUB_TOKEN');
  const cohereKeys = extractKeys('COHERE_API_KEY');
  
  // Return session info with actual key counts
  res.json({
    token,
    expiresAt: session.expiresAt,
    services: {
      perplexity: perplexityKeys.length,
      gemini: geminiKeys.length,
      groq: groqKeys.length,
      openai: openaiKeys.length,
      openrouter: openrouterKeys.length,
      github: githubKeys.length,
      cohere: cohereKeys.length
    }
  });
});

// Get API key for a specific service
app.post('/api/keys/get', authenticateSession, (req, res) => {
  const { service } = req.body;
  
  if (!service) {
    return res.status(400).json({ error: 'Service not specified' });
  }
  
  const keyMap = {
    perplexity: 'PERPLEXITY_API_KEY',
    gemini: 'GOOGLE_API_KEY',
    groq: 'GROQ_API_KEY',
    openai: 'OPENAI_API_KEY',
    openrouter: 'OPENROUTER_API_KEY',
    github: 'GITHUB_TOKEN',
    cohere: 'COHERE_API_KEY'
  };
  
  const baseKey = keyMap[service];
  if (!baseKey) {
    return res.status(400).json({ error: 'Invalid service' });
  }
  
  const keys = extractKeys(baseKey);
  if (keys.length === 0) {
    return res.status(404).json({ error: `No keys configured for ${service}` });
  }
  
  // Get current index for this service
  const currentIndex = req.session.keyIndices[service] || 0;
  const key = keys[currentIndex % keys.length];
  
  // Obfuscate the key for logging (show only first 10 chars)
  const obfuscatedKey = key.substring(0, 10) + '...';
  
  res.json({
    key,
    obfuscated: obfuscatedKey,
    index: currentIndex,
    total: keys.length
  });
});

// Rotate to next key for a service
app.post('/api/keys/rotate', authenticateSession, (req, res) => {
  const { service } = req.body;
  
  if (!service || !req.session.keyIndices.hasOwnProperty(service)) {
    return res.status(400).json({ error: 'Invalid service' });
  }
  
  // Increment the index
  req.session.keyIndices[service] = (req.session.keyIndices[service] + 1) % 1000;
  
  res.json({
    success: true,
    newIndex: req.session.keyIndices[service]
  });
});

// Get service status (which services have keys configured)
app.get('/api/services/status', authenticateSession, (req, res) => {
  res.json({
    groq: extractKeys('GROQ_API_KEY').length > 0,
    gemini: extractKeys('GOOGLE_API_KEY').length > 0,
    perplexity: extractKeys('PERPLEXITY_API_KEY').length > 0,
    openai: extractKeys('OPENAI_API_KEY').length > 0,
    openrouter: extractKeys('OPENROUTER_API_KEY').length > 0,
    github: extractKeys('GITHUB_TOKEN').length > 0,
    cohere: extractKeys('COHERE_API_KEY').length > 0
  });
});

// Add a new endpoint to get key counts
app.get('/api/keys/count', authenticateSession, (req, res) => {
  res.json({
    groq: extractKeys('GROQ_API_KEY').length,
    gemini: extractKeys('GOOGLE_API_KEY').length,
    perplexity: extractKeys('PERPLEXITY_API_KEY').length,
    openai: extractKeys('OPENAI_API_KEY').length,
    openrouter: extractKeys('OPENROUTER_API_KEY').length,
    github: extractKeys('GITHUB_TOKEN').length,
    cohere: extractKeys('COHERE_API_KEY').length
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
  console.log('Configured services:');
  
  const groqKeys = extractKeys('GROQ_API_KEY');
  const geminiKeys = extractKeys('GOOGLE_API_KEY');
  const perplexityKeys = extractKeys('PERPLEXITY_API_KEY');
  const openaiKeys = extractKeys('OPENAI_API_KEY');
  const openrouterKeys = extractKeys('OPENROUTER_API_KEY');
  const githubKeys = extractKeys('GITHUB_TOKEN');
  const cohereKeys = extractKeys('COHERE_API_KEY');
  
  console.log('- Groq:', groqKeys.length, 'keys');
  console.log('- Gemini:', geminiKeys.length, 'keys');
  console.log('- Perplexity:', perplexityKeys.length, 'keys');
  console.log('- OpenAI:', openaiKeys.length, 'keys');
  console.log('- OpenRouter:', openrouterKeys.length, 'keys');
  console.log('- GitHub:', githubKeys.length, 'keys');
  console.log('- Cohere:', cohereKeys.length, 'keys');
  
  // Show total keys
  const totalKeys = groqKeys.length + geminiKeys.length + perplexityKeys.length + 
                    openaiKeys.length + openrouterKeys.length + githubKeys.length + cohereKeys.length;
  console.log('Total API keys configured:', totalKeys);
  
  if (totalKeys === 0) {
    console.warn('\n⚠️  WARNING: No API keys found!');
    console.warn('Please ensure your .env.local or .env file contains API keys.');
    console.warn('Example: GROQ_API_KEY1="your-key-here"');
  }
});
