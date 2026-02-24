// server.js (ESM)

import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";
import { v4 as uuidv4 } from "uuid";
import FormData from "form-data";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables - prefer .env.local over .env
const envLocalPath = path.join(__dirname, ".env.local");
const envPath = path.join(__dirname, ".env");

if (fs.existsSync(envLocalPath)) {
  dotenv.config({ path: envLocalPath });
  console.log("Loaded configuration from .env.local");
} else if (fs.existsSync(envPath)) {
  dotenv.config({ path: envPath });
  console.log("Loaded configuration from .env");
} else {
  dotenv.config();
  console.log("Using default environment variables");
}

const app = express();
const PORT = process.env.PORT || 3001;

// Trust proxy - configure based on deployment environment
// For Railway/Render/Heroku, use 1 to trust the first proxy
// For development, don't trust any proxy
const trustProxyConfig = process.env.NODE_ENV === "production" ? 1 : false;
app.set("trust proxy", trustProxyConfig);

// Security middleware
app.use(helmet());

// ===============================
// ✅ FIX: parse comma-separated FRONTEND_URL into multiple origins
// Example env:
// FRONTEND_URL="https://multi-ais-chat.netlify.app,https://aifiestaa.netlify.app,https://pintukr.in"
// ===============================
const envOrigins = (process.env.FRONTEND_URL || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// Use the first origin as a "primary" URL for headers like HTTP-Referer
const primaryFrontendUrl = envOrigins[0] || "http://localhost:5173";

// Define allowed origins for CORS
const allowedOrigins = new Set([
  ...envOrigins,
  "http://localhost:5173",
  "http://localhost:3000",
]);

app.use(
  cors({
    origin(origin, callback) {
      // Allow requests with no origin (curl, mobile apps, server-to-server)
      if (!origin) return callback(null, true);

      if (allowedOrigins.has(origin)) return callback(null, true);

      return callback(new Error(`Not allowed by CORS: ${origin}`), false);
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "X-Session-Token"],
  }),
);

// Base64-encoded images can exceed the raw upload size; align with 10MB frontend cap.
app.use(express.json({ limit: "20mb" }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  // Skip rate limiting in development
  skip: () => process.env.NODE_ENV === "development",
  message: "Too many requests from this IP, please try again later.",
  // Explicitly validate the trust proxy setting
  validate: {
    trustProxy: false, // Disable the built-in validation since we're handling it manually
    xForwardedForHeader: false, // Disable this validation too
  },
});
app.use("/api/", limiter);

// Session storage (in production, use Redis or a database)
const sessions = new Map();
const SESSION_DURATION = 60 * 60 * 1000; // 1 hour

// Cleanup expired sessions
setInterval(
  () => {
    const now = Date.now();
    for (const [token, session] of sessions.entries()) {
      if (now > session.expiresAt) sessions.delete(token);
    }
  },
  5 * 60 * 1000,
); // Clean every 5 minutes

// Cache for extracted keys - computed once at startup
const keyCache = new Map();

// Helper to extract API keys from environment (with caching)
function extractKeys(baseKeyName) {
  // Return cached result if available
  if (keyCache.has(baseKeyName)) return keyCache.get(baseKeyName);

  const keys = new Set();
  const envVarMap = {
    GOOGLE_API_KEY: "GOOGLE_API_KEY",
    GROQ_API_KEY: "GROQ_API_KEY",
    SAMBANOVAAI_API_KEY: "SAMBANOVAAI_API_KEY",
    OPENROUTER_API_KEY: "OPENROUTER_API_KEY",
    GITHUB_TOKEN: "GITHUB_TOKEN",
    COHERE_API_KEY: "COHERE_API_KEY",
    XAI_API_KEY: "XAI_API_KEY",
    FASTROUTER_API_KEY: "FASTROUTER_API_KEY",
  };

  const base = envVarMap[baseKeyName] || baseKeyName;

  // Direct key
  if (process.env[base]) keys.add(process.env[base]);

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
    console.log(
      `No keys found for ${baseKeyName}. Checked: ${base}, ${base}1-20, ${base}_1-20`,
    );
  }

  const result = Array.from(keys);
  keyCache.set(baseKeyName, result);
  return result;
}

function getOpenAICompatibleKeys() {
  return Array.from(
    new Set([
      ...extractKeys("FASTROUTER_API_KEY"),
      ...extractKeys("SAMBANOVAAI_API_KEY"),
    ]),
  );
}

// Pre-warm the key cache at startup
function initializeKeyCache() {
  const services = [
    "GROQ_API_KEY",
    "GOOGLE_API_KEY",
    "SAMBANOVAAI_API_KEY",
    "OPENROUTER_API_KEY",
    "GITHUB_TOKEN",
    "COHERE_API_KEY",
    "XAI_API_KEY",
    "FASTROUTER_API_KEY",
  ];
  services.forEach(extractKeys);
}

// Middleware to verify session token
function authenticateSession(req, res, next) {
  const token = req.headers["x-session-token"];

  if (!token)
    return res.status(401).json({ error: "No session token provided" });

  const session = sessions.get(token);

  if (!session || Date.now() > session.expiresAt) {
    sessions.delete(token);
    return res.status(401).json({ error: "Session expired or invalid" });
  }

  // Refresh session
  session.expiresAt = Date.now() + SESSION_DURATION;
  req.session = session;
  next();
}

// Middleware to prevent caching of sensitive data
function preventCache(req, res, next) {
  res.set({
    "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
    Pragma: "no-cache",
    Expires: "0",
    "Surrogate-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
  });
  next();
}

// Initialize session - client calls this first
app.post("/api/session/init", (req, res) => {
  const token = uuidv4();
  const session = {
    id: token,
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_DURATION,
    keyIndices: {
      gemini: 0,
      groq: 0,
      openai: 0,
      openrouter: 0,
      github: 0,
      cohere: 0,
      xai: 0,
      fastrouter: 0,
    },
  };

  sessions.set(token, session);

  // Get actual key counts for each service
  const groqKeys = extractKeys("GROQ_API_KEY");
  const geminiKeys = extractKeys("GOOGLE_API_KEY");
  const openaiKeys = getOpenAICompatibleKeys();
  const openrouterKeys = extractKeys("OPENROUTER_API_KEY");
  const githubKeys = extractKeys("GITHUB_TOKEN");
  const cohereKeys = extractKeys("COHERE_API_KEY");
  const xaiKeys = extractKeys("XAI_API_KEY");
  const fastrouterKeys = extractKeys("FASTROUTER_API_KEY");

  // Return session info with actual key counts
  res.json({
    token,
    expiresAt: session.expiresAt,
    services: {
      gemini: geminiKeys.length,
      groq: groqKeys.length,
      openai: openaiKeys.length,
      openrouter: openrouterKeys.length,
      github: githubKeys.length,
      cohere: cohereKeys.length,
      xai: xaiKeys.length,
      fastrouter: fastrouterKeys.length,
    },
  });
});

// Get API key for a specific service
app.post("/api/keys/get", authenticateSession, preventCache, (req, res) => {
  const { service } = req.body;

  if (!service) return res.status(400).json({ error: "Service not specified" });

  if (service === "openai") {
    const keys = getOpenAICompatibleKeys();
    if (keys.length === 0) {
      return res.status(404).json({ error: "No keys configured for openai" });
    }

    const currentIndex = req.session.keyIndices.openai || 0;
    const key = keys[currentIndex % keys.length];

    res.type("application/octet-stream");
    const responseData = { key, index: currentIndex, total: keys.length };
    const buffer = Buffer.from(JSON.stringify(responseData));
    return res.send(buffer);
  }

  const keyMap = {
    gemini: "GOOGLE_API_KEY",
    groq: "GROQ_API_KEY",
    openrouter: "OPENROUTER_API_KEY",
    github: "GITHUB_TOKEN",
    cohere: "COHERE_API_KEY",
    xai: "XAI_API_KEY",
    fastrouter: "FASTROUTER_API_KEY",
  };

  const baseKey = keyMap[service];
  if (!baseKey) return res.status(400).json({ error: "Invalid service" });

  const keys = extractKeys(baseKey);
  if (keys.length === 0)
    return res.status(404).json({ error: `No keys configured for ${service}` });

  // Get current index for this service
  const currentIndex = req.session.keyIndices[service] || 0;
  const key = keys[currentIndex % keys.length];

  // Set response type to prevent browser preview/caching
  res.type("application/octet-stream");

  // Send the response as a buffer to prevent text preview
  const responseData = { key, index: currentIndex, total: keys.length };
  const buffer = Buffer.from(JSON.stringify(responseData));
  res.send(buffer);
});

// Rotate to next key for a service
app.post("/api/keys/rotate", authenticateSession, (req, res) => {
  const { service } = req.body;

  if (
    !service ||
    !Object.prototype.hasOwnProperty.call(req.session.keyIndices, service)
  ) {
    return res.status(400).json({ error: "Invalid service" });
  }

  // Increment the index
  req.session.keyIndices[service] =
    (req.session.keyIndices[service] + 1) % 1000;

  res.json({ success: true, newIndex: req.session.keyIndices[service] });
});

// Get service status (which services have keys configured)
app.get("/api/services/status", authenticateSession, (req, res) => {
  res.json({
    groq: extractKeys("GROQ_API_KEY").length > 0,
    gemini: extractKeys("GOOGLE_API_KEY").length > 0,
    openai: getOpenAICompatibleKeys().length > 0,
    openrouter: extractKeys("OPENROUTER_API_KEY").length > 0,
    github: extractKeys("GITHUB_TOKEN").length > 0,
    cohere: extractKeys("COHERE_API_KEY").length > 0,
    xai: extractKeys("XAI_API_KEY").length > 0,
    fastrouter: extractKeys("FASTROUTER_API_KEY").length > 0,
  });
});

// Add a new endpoint to get key counts
app.get("/api/keys/count", authenticateSession, (req, res) => {
  res.json({
    groq: extractKeys("GROQ_API_KEY").length,
    gemini: extractKeys("GOOGLE_API_KEY").length,
    openai: getOpenAICompatibleKeys().length,
    openrouter: extractKeys("OPENROUTER_API_KEY").length,
    github: extractKeys("GITHUB_TOKEN").length,
    cohere: extractKeys("COHERE_API_KEY").length,
    xai: extractKeys("XAI_API_KEY").length,
    fastrouter: extractKeys("FASTROUTER_API_KEY").length,
  });
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// List all available SambaNova models for UI dropdown selection
app.get("/api/models/openai", authenticateSession, async (req, res) => {
  const keys = extractKeys("SAMBANOVAAI_API_KEY");
  if (keys.length === 0) {
    return res.status(503).json({ error: "No SambaNova API keys available" });
  }

  try {
    const models = await getSambaNovaModels(keys[0]);
    return res.json({
      models: sanitizeModelIds(models),
      source: "sambanova",
      success: true,
    });
  } catch (error) {
    const details = error instanceof Error ? error.message : String(error);
    return res.status(500).json({
      error: "Failed to fetch SambaNova models",
      details: compactText(details),
      success: false,
    });
  }
});

// =============================================================================
// SECURE PROXY ENDPOINTS - AI API calls made server-side (keys never sent to client)
// =============================================================================

// Helper to get next key with rotation
function getNextKey(session, service, baseKeyName) {
  const keys = extractKeys(baseKeyName);
  if (keys.length === 0) return null;
  const currentIndex = session.keyIndices[service] || 0;
  return {
    key: keys[currentIndex % keys.length],
    index: currentIndex,
    total: keys.length,
  };
}

// Helper to rotate key on failure
function rotateKeyOnFailure(session, service) {
  session.keyIndices[service] = ((session.keyIndices[service] || 0) + 1) % 1000;
}

const OPENROUTER_MODEL_CACHE_TTL_MS = 5 * 60 * 1000;
const OPENROUTER_DEFAULT_MODELS = [
  "qwen/qwen3-coder:free",
  "upstage/solar-pro-3:free",
  "openrouter/free",
];
const OPENROUTER_PREFERRED_MODELS = [
  "qwen/qwen3-coder:free",
  "openai/gpt-oss-20b:free",
  "openai/gpt-oss-120b:free",
  "upstage/solar-pro-3:free",
  "stepfun/step-3.5-flash:free",
];
let openRouterModelCache = { expiresAt: 0, models: OPENROUTER_DEFAULT_MODELS };

const SAMBANOVA_MODEL_CACHE_TTL_MS = 5 * 60 * 1000;
const SAMBANOVA_DEFAULT_MODELS = ["Meta-Llama-3.1-8B-Instruct"];
let sambaNovaModelCache = { expiresAt: 0, models: SAMBANOVA_DEFAULT_MODELS };

function compactText(value, max = 200) {
  if (!value) return "";
  return String(value).replace(/\s+/g, " ").trim().slice(0, max);
}

function parseErrorMessage(rawText, fallback) {
  if (!rawText) return fallback;
  try {
    const parsed = JSON.parse(rawText);
    const message =
      parsed?.error?.message ||
      parsed?.message ||
      parsed?.detail ||
      parsed?.error_description;
    return compactText(message, 260) || fallback;
  } catch {
    return compactText(rawText, 260) || fallback;
  }
}

function isPreferredOpenRouterModel(modelId) {
  if (typeof modelId !== "string" || !modelId.endsWith(":free")) return false;

  const lower = modelId.toLowerCase();
  if (lower.includes("vl") || lower.includes("vision")) return false;
  if (lower.includes("image") || lower.includes("audio")) return false;
  if (lower.includes("transcribe") || lower.includes("embedding")) return false;
  if (lower.includes("thinking")) return false;
  return true;
}

async function fetchOpenRouterModels(apiKey) {
  const response = await fetch("https://openrouter.ai/api/v1/models/user", {
    method: "GET",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "HTTP-Referer": primaryFrontendUrl,
      "X-Title": "AI Chat Fusion",
    },
  });

  if (!response.ok) {
    const raw = await response.text();
    const details = parseErrorMessage(
      raw,
      `OpenRouter model list failed (${response.status})`,
    );
    throw new Error(details);
  }

  const data = await response.json();
  const available = Array.isArray(data?.data)
    ? data.data.map((item) => item?.id).filter(isPreferredOpenRouterModel)
    : [];

  const ordered = [];
  for (const preferred of OPENROUTER_PREFERRED_MODELS) {
    if (available.includes(preferred)) ordered.push(preferred);
  }
  for (const model of available) {
    if (!ordered.includes(model)) ordered.push(model);
  }

  const limited = ordered.slice(0, 10);
  if (!limited.includes("openrouter/free")) limited.push("openrouter/free");
  if (limited.length === 0) return OPENROUTER_DEFAULT_MODELS;

  return limited;
}

async function getOpenRouterModels(apiKey) {
  if (
    openRouterModelCache.expiresAt > Date.now() &&
    openRouterModelCache.models.length > 0
  ) {
    return openRouterModelCache.models;
  }

  try {
    const models = await fetchOpenRouterModels(apiKey);
    openRouterModelCache = {
      expiresAt: Date.now() + OPENROUTER_MODEL_CACHE_TTL_MS,
      models,
    };
    return models;
  } catch (error) {
    const details =
      error instanceof Error ? error.message : "Unknown model-list error";
    console.warn(`[OpenRouter] using fallback model list: ${details}`);
    openRouterModelCache = {
      expiresAt: Date.now() + OPENROUTER_MODEL_CACHE_TTL_MS,
      models: OPENROUTER_DEFAULT_MODELS,
    };
    return OPENROUTER_DEFAULT_MODELS;
  }
}

function invalidateOpenRouterModelCache() {
  openRouterModelCache.expiresAt = 0;
}

function buildOpenRouterRequestModels(modelCandidates) {
  const unique = Array.from(
    new Set(
      (Array.isArray(modelCandidates) ? modelCandidates : []).filter(
        (model) => typeof model === "string" && model.trim().length > 0,
      ),
    ),
  );

  const selected = unique.slice(0, 3);

  if (!selected.includes("openrouter/free")) {
    if (selected.length < 3) selected.push("openrouter/free");
    else selected[selected.length - 1] = "openrouter/free";
  }

  return Array.from(new Set(selected)).slice(0, 3);
}

function extractOpenRouterContent(data) {
  const firstMessage = data?.choices?.[0]?.message;
  const content = firstMessage?.content;

  if (typeof content === "string" && content.trim()) return content.trim();

  if (Array.isArray(content)) {
    const text = content
      .map((part) =>
        typeof part === "string"
          ? part
          : typeof part?.text === "string"
            ? part.text
            : "",
      )
      .join("")
      .trim();
    if (text) return text;
  }

  if (
    typeof firstMessage?.reasoning === "string" &&
    firstMessage.reasoning.trim()
  ) {
    return firstMessage.reasoning.trim();
  }

  return "";
}

function isSambaNovaChatModel(modelId) {
  if (typeof modelId !== "string" || !modelId.trim()) return false;

  const lower = modelId.toLowerCase();
  if (lower.includes("embedding")) return false;
  if (lower.includes("whisper")) return false;
  if (lower.includes("audio")) return false;
  if (lower.includes("transcribe")) return false;
  if (lower.includes("tts")) return false;

  return true;
}

function sanitizeModelIds(models) {
  return Array.from(
    new Set(
      (Array.isArray(models) ? models : []).filter(
        (modelId) => typeof modelId === "string" && modelId.trim().length > 0,
      ),
    ),
  );
}

async function fetchSambaNovaModels(apiKey) {
  const response = await fetch("https://api.sambanova.ai/v1/models", {
    method: "GET",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
  });

  if (!response.ok) {
    const raw = await response.text();
    const details = parseErrorMessage(
      raw,
      `SambaNova model list failed (${response.status})`,
    );
    throw new Error(details);
  }

  const data = await response.json();
  const available = sanitizeModelIds(
    Array.isArray(data?.data) ? data.data.map((item) => item?.id) : [],
  );

  if (available.length === 0) return SAMBANOVA_DEFAULT_MODELS;
  return available;
}

async function getSambaNovaModels(apiKey) {
  if (
    sambaNovaModelCache.expiresAt > Date.now() &&
    sambaNovaModelCache.models.length > 0
  ) {
    return sambaNovaModelCache.models;
  }

  try {
    const models = await fetchSambaNovaModels(apiKey);
    sambaNovaModelCache = {
      expiresAt: Date.now() + SAMBANOVA_MODEL_CACHE_TTL_MS,
      models,
    };
    return models;
  } catch (error) {
    const details =
      error instanceof Error ? error.message : "Unknown model-list error";
    console.warn(`[SambaNova] using fallback model list: ${details}`);
    sambaNovaModelCache = {
      expiresAt: Date.now() + SAMBANOVA_MODEL_CACHE_TTL_MS,
      models: SAMBANOVA_DEFAULT_MODELS,
    };
    return SAMBANOVA_DEFAULT_MODELS;
  }
}

function invalidateSambaNovaModelCache() {
  sambaNovaModelCache.expiresAt = 0;
}

function getPreferredSambaNovaModel(models) {
  const allModels = sanitizeModelIds(models);
  const chatModels = allModels.filter((modelId) => isSambaNovaChatModel(modelId));
  const candidates = chatModels.length > 0 ? chatModels : allModels;
  if (candidates.length === 0) return SAMBANOVA_DEFAULT_MODELS[0];
  return candidates[Math.floor(Date.now() / 1000) % candidates.length];
}

function parseBase64Image(image) {
  if (typeof image !== "string") {
    return { error: "Invalid image data" };
  }

  const match = image.match(/^data:([^;]+);base64,([\s\S]+)$/);
  const mimeType = match?.[1] || "image/png";
  let base64Data = match?.[2] || image;

  base64Data = base64Data.replace(/\s/g, "");

  if (!base64Data) {
    return { error: "Invalid image data" };
  }

  return { mimeType, base64Data };
}

// Proxy endpoint for Groq API (with retry on rate limit)
app.post("/api/proxy/groq", authenticateSession, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });

  const keys = extractKeys("GROQ_API_KEY");
  const maxRetries = Math.min(keys.length, 5);

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const keyData = getNextKey(req.session, "groq", "GROQ_API_KEY");
    if (!keyData)
      return res.status(503).json({ error: "No Groq API keys available" });

    try {
      const response = await fetch(
        "https://api.groq.com/openai/v1/chat/completions",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${keyData.key}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: "llama-3.1-8b-instant",
            messages: [
              {
                role: "system",
                content:
                  "You are Groq AI, an ultra-fast AI assistant. Provide concise, helpful responses.",
              },
              { role: "user", content: message },
            ],
            max_tokens: 1000,
            temperature: 0.7,
          }),
        },
      );

      if (response.ok) {
        const data = await response.json();
        return res.json({
          content: data.choices?.[0]?.message?.content || "",
          model: "llama-3.1-8b-instant",
          source: "groq",
          success: true,
        });
      }

      if (response.status === 429 || response.status === 401) {
        rotateKeyOnFailure(req.session, "groq");
        continue;
      }

      return res.status(response.status).json({
        error: "Groq API error",
        status: response.status,
      });
    } catch {
      rotateKeyOnFailure(req.session, "groq");
      continue;
    }
  }

  res
    .status(429)
    .json({ error: "All Groq API keys rate limited", success: false });
});

// Proxy endpoint for Gemini API via FastRouter (with retry on rate limit)
app.post("/api/proxy/gemini", authenticateSession, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });

  const keys = extractKeys("FASTROUTER_API_KEY");
  const maxRetries = Math.min(keys.length, 5);

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const keyData = getNextKey(req.session, "fastrouter", "FASTROUTER_API_KEY");
    if (!keyData)
      return res
        .status(503)
        .json({ error: "No FastRouter API keys available for Gemini" });

    try {
      const response = await fetch(
        "https://go.fastrouter.ai/api/v1/chat/completions",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${keyData.key}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: "google/gemini-2.5-flash",
            messages: [
              {
                role: "system",
                content: "You are Gemini, a helpful AI assistant by Google.",
              },
              { role: "user", content: message },
            ],
            max_tokens: 4096,
            temperature: 0.7,
          }),
        },
      );

      if (response.ok) {
        const data = await response.json();
        return res.json({
          content: data.choices?.[0]?.message?.content || "",
          model: "google/gemini-2.5-flash",
          source: "gemini",
          success: true,
        });
      }

      if ([429, 401, 403].includes(response.status)) {
        rotateKeyOnFailure(req.session, "fastrouter");
        continue;
      }

      return res
        .status(response.status)
        .json({ error: "Gemini API error", status: response.status });
    } catch {
      rotateKeyOnFailure(req.session, "fastrouter");
      continue;
    }
  }

  res
    .status(429)
    .json({ error: "All FastRouter API keys rate limited", success: false });
});

// Proxy endpoint for Cohere API
app.post("/api/proxy/cohere", authenticateSession, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });

  const keys = extractKeys("COHERE_API_KEY");
  const maxRetries = Math.min(keys.length, 5);
  const modelCandidates = [
    "command-a-03-2025",
    "command-r-plus-08-2024",
    "command-r7b-12-2024",
  ];
  const attemptErrors = [];

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const keyData = getNextKey(req.session, "cohere", "COHERE_API_KEY");
    if (!keyData) {
      return res.status(503).json({ error: "No Cohere API keys available" });
    }

    let shouldRotateKey = false;

    for (const model of modelCandidates) {
      try {
        const response = await fetch("https://api.cohere.com/v2/chat", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${keyData.key}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model,
            messages: [{ role: "user", content: message }],
            temperature: 0.7,
          }),
        });

        const raw = await response.text();

        if (response.ok) {
          const data = JSON.parse(raw);
          const content = data?.message?.content?.[0]?.text || "";

          if (!content.trim()) {
            attemptErrors.push(`${model}: empty response`);
            continue;
          }

          return res.json({
            content,
            model,
            source: "cohere",
            success: true,
          });
        }

        const details = parseErrorMessage(
          raw,
          `Cohere API error (${response.status})`,
        );
        attemptErrors.push(`${model} (${response.status}): ${details}`);

        if (response.status === 401 || response.status === 429) {
          shouldRotateKey = true;
          break;
        }

        if (
          response.status === 404 ||
          (response.status === 400 &&
            /model|removed|not found|deprecated/i.test(details))
        ) {
          continue;
        }
      } catch (error) {
        const details =
          error instanceof Error ? error.message : "Unknown Cohere error";
        attemptErrors.push(`${model}: ${compactText(details)}`);
      }
    }

    if (shouldRotateKey) {
      rotateKeyOnFailure(req.session, "cohere");
    }
  }

  return res.status(503).json({
    error: "All Cohere models failed",
    details: compactText(attemptErrors.join(" | "), 500),
    success: false,
  });
});

// Proxy endpoint for GitHub Models API
app.post("/api/proxy/github", authenticateSession, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });

  const keyData = getNextKey(req.session, "github", "GITHUB_TOKEN");
  if (!keyData)
    return res.status(503).json({ error: "No GitHub API tokens available" });

  const models = [
    "xai/grok-3-mini",
    "deepseek/DeepSeek-V3-0324",
    "openai/gpt-4.1",
  ];
  const selectedModel = models[Math.floor(Date.now() / 1000) % models.length];

  try {
    const response = await fetch(
      "https://models.github.ai/inference/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${keyData.key}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: selectedModel,
          messages: [
            {
              role: "system",
              content: "You are GitHub AI, an advanced AI assistant.",
            },
            { role: "user", content: message },
          ],
          max_tokens: 1000,
          temperature: 0.7,
        }),
      },
    );

    if (!response.ok) {
      if (response.status === 429 || response.status === 401)
        rotateKeyOnFailure(req.session, "github");
      return res
        .status(response.status)
        .json({ error: "GitHub API error", status: response.status });
    }

    const data = await response.json();
    res.json({
      content: data.choices?.[0]?.message?.content || "",
      model: selectedModel,
      source: "github",
      success: true,
    });
  } catch {
    res
      .status(500)
      .json({ error: "Failed to call GitHub API", success: false });
  }
});

// Proxy endpoint for OpenRouter API
app.post("/api/proxy/openrouter", authenticateSession, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });

  const keys = extractKeys("OPENROUTER_API_KEY");
  const maxRetries = Math.min(keys.length, 5);
  const attemptErrors = [];

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const keyData = getNextKey(req.session, "openrouter", "OPENROUTER_API_KEY");
    if (!keyData) {
      return res.status(503).json({ error: "No OpenRouter API keys available" });
    }

    const modelCandidates = await getOpenRouterModels(keyData.key);
    const requestModels = buildOpenRouterRequestModels(modelCandidates);

    try {
      const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${keyData.key}`,
          "Content-Type": "application/json",
          "HTTP-Referer": primaryFrontendUrl,
          "X-Title": "AI Chat Fusion",
        },
        body: JSON.stringify({
          models: requestModels,
          provider: {
            allow_fallbacks: true,
            sort: "throughput",
          },
          messages: [
            {
              role: "system",
              content: "You are OpenRouter AI, a flexible AI assistant.",
            },
            { role: "user", content: message },
          ],
          max_tokens: 1000,
          temperature: 0.5,
        }),
      });

      const raw = await response.text();

      if (response.ok) {
        const data = JSON.parse(raw);
        const content = extractOpenRouterContent(data);
        if (!content) {
          attemptErrors.push("OpenRouter: empty content");
          continue;
        }

        return res.json({
          content,
          model: data?.model || "openrouter/free",
          source: "openrouter",
          success: true,
        });
      }

      const details = parseErrorMessage(
        raw,
        `OpenRouter API error (${response.status})`,
      );
      attemptErrors.push(`${response.status}: ${details}`);

      if (response.status === 401 || response.status === 429) {
        rotateKeyOnFailure(req.session, "openrouter");
        continue;
      }

      if (response.status === 400 || response.status === 404) {
        invalidateOpenRouterModelCache();
      }
    } catch (error) {
      const details =
        error instanceof Error ? error.message : "Unknown OpenRouter error";
      attemptErrors.push(`network: ${compactText(details)}`);
    }
  }

  return res.status(503).json({
    error: "All OpenRouter attempts failed",
    details: compactText(attemptErrors.join(" | "), 500),
    success: false,
  });
});

// Proxy endpoint for xAI (Grok) via FastRouter API
app.post("/api/proxy/xai", authenticateSession, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });

  const keyData = getNextKey(req.session, "fastrouter", "FASTROUTER_API_KEY");
  if (!keyData)
    return res
      .status(503)
      .json({ error: "No FastRouter API keys available for xAI" });

  try {
    const response = await fetch(
      "https://go.fastrouter.ai/api/v1/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${keyData.key}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "x-ai/grok-3-beta",
          messages: [
            {
              role: "system",
              content:
                "You are Grok, an AI assistant by xAI. Be helpful, witty, and insightful.",
            },
            { role: "user", content: message },
          ],
          max_tokens: 2048,
          temperature: 0.7,
        }),
      },
    );

    if (!response.ok) {
      if (response.status === 429 || response.status === 401)
        rotateKeyOnFailure(req.session, "fastrouter");
      return res
        .status(response.status)
        .json({ error: "xAI API error", status: response.status });
    }

    const data = await response.json();
    res.json({
      content: data.choices?.[0]?.message?.content || "",
      model: "x-ai/grok-3-beta",
      source: "xai",
      success: true,
    });
  } catch {
    res.status(500).json({ error: "Failed to call xAI API", success: false });
  }
});

// Proxy endpoint for OpenAI-compatible API via SambaNova
app.post("/api/proxy/openai", authenticateSession, async (req, res) => {
  const { message, model } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });
  const requestedModel =
    typeof model === "string" && model.trim().length > 0 ? model.trim() : null;

  let fastRouterFailure = null;
  if (!requestedModel) {
    const fastRouterKeyData = getNextKey(
      req.session,
      "fastrouter",
      "FASTROUTER_API_KEY",
    );
    if (fastRouterKeyData) {
      try {
        const fastRouterResponse = await fetch(
          "https://go.fastrouter.ai/api/v1/chat/completions",
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${fastRouterKeyData.key}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              model: "openai/gpt-4o",
              messages: [
                { role: "system", content: "You are a helpful AI assistant." },
                { role: "user", content: message },
              ],
              max_tokens: 1000,
              temperature: 0.7,
            }),
          },
        );

        if (fastRouterResponse.ok) {
          const fastRouterData = await fastRouterResponse.json();
          return res.json({
            content: fastRouterData.choices?.[0]?.message?.content || "",
            model: fastRouterData?.model || "openai/gpt-4o",
            source: "openai",
            success: true,
          });
        }

        if (
          fastRouterResponse.status === 429 ||
          fastRouterResponse.status === 401
        ) {
          rotateKeyOnFailure(req.session, "fastrouter");
        }
        fastRouterFailure = {
          status: fastRouterResponse.status,
          error: "OpenAI API error",
        };
      } catch {
        fastRouterFailure = {
          status: 500,
          error: "Failed to call OpenAI API",
        };
        // Keep existing behavior and continue to SambaNova as an added path.
      }
    }
  }

  const keys = extractKeys("SAMBANOVAAI_API_KEY");
  const maxRetries = Math.min(keys.length, 5);
  const attemptErrors = [];

  if (maxRetries === 0) {
    if (fastRouterFailure) {
      return res
        .status(fastRouterFailure.status)
        .json({ error: fastRouterFailure.error, success: false });
    }
    return res
      .status(503)
      .json({
        error:
          "No OpenAI-compatible keys available (FastRouter/SambaNova)",
      });
  }

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const keyData = getNextKey(req.session, "openai", "SAMBANOVAAI_API_KEY");
    if (!keyData) {
      return res
        .status(503)
        .json({
          error:
            "No OpenAI-compatible keys available (FastRouter/SambaNova)",
        });
    }

    const modelCandidates = await getSambaNovaModels(keyData.key);
    const selectedModel =
      requestedModel || getPreferredSambaNovaModel(modelCandidates);

    try {
      const response = await fetch(
        "https://api.sambanova.ai/v1/chat/completions",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${keyData.key}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: selectedModel,
            messages: [
              { role: "system", content: "You are a helpful AI assistant." },
              { role: "user", content: message },
            ],
            max_tokens: 1000,
            temperature: 0.7,
          }),
        },
      );

      const raw = await response.text();

      if (response.ok) {
        const data = JSON.parse(raw);
        const content = data?.choices?.[0]?.message?.content;
        if (!content || !content.trim()) {
          attemptErrors.push(`${selectedModel}: empty response`);
          continue;
        }

        return res.json({
          content,
          model: data?.model || selectedModel,
          source: "openai",
          success: true,
        });
      }

      const details = parseErrorMessage(
        raw,
        `SambaNova API error (${response.status})`,
      );
      let fallbackAttempted = false;

      if (
        requestedModel &&
        selectedModel === requestedModel &&
        (response.status === 400 || response.status === 404)
      ) {
        const fallbackModel =
          modelCandidates.find(
            (modelId) =>
              modelId !== selectedModel && isSambaNovaChatModel(modelId),
          ) ||
          modelCandidates.find((modelId) => modelId !== selectedModel);

        if (fallbackModel) {
          fallbackAttempted = true;
          try {
            const fallbackResponse = await fetch(
              "https://api.sambanova.ai/v1/chat/completions",
              {
                method: "POST",
                headers: {
                  Authorization: `Bearer ${keyData.key}`,
                  "Content-Type": "application/json",
                },
                body: JSON.stringify({
                  model: fallbackModel,
                  messages: [
                    {
                      role: "system",
                      content: "You are a helpful AI assistant.",
                    },
                    { role: "user", content: message },
                  ],
                  max_tokens: 1000,
                  temperature: 0.7,
                }),
              },
            );

            const fallbackRaw = await fallbackResponse.text();

            if (fallbackResponse.ok) {
              const fallbackData = JSON.parse(fallbackRaw);
              const fallbackContent = fallbackData?.choices?.[0]?.message?.content;
              if (fallbackContent && fallbackContent.trim()) {
                return res.json({
                  content: fallbackContent,
                  model: fallbackData?.model || fallbackModel,
                  source: "openai",
                  success: true,
                });
              }

              attemptErrors.push(
                `${selectedModel} (${response.status}): ${details} | fallback ${fallbackModel}: empty response`,
              );
            } else {
              const fallbackDetails = parseErrorMessage(
                fallbackRaw,
                `SambaNova API error (${fallbackResponse.status})`,
              );
              attemptErrors.push(
                `${selectedModel} (${response.status}): ${details} | fallback ${fallbackModel} (${fallbackResponse.status}): ${fallbackDetails}`,
              );

              if (fallbackResponse.status === 400 || fallbackResponse.status === 404) {
                invalidateSambaNovaModelCache();
              }

              if (fallbackResponse.status === 401 || fallbackResponse.status === 429) {
                rotateKeyOnFailure(req.session, "openai");
              }
            }
          } catch (fallbackError) {
            const fallbackDetails =
              fallbackError instanceof Error
                ? fallbackError.message
                : "Unknown SambaNova fallback error";
            attemptErrors.push(
              `${selectedModel} (${response.status}): ${details} | fallback ${fallbackModel}: ${compactText(fallbackDetails)}`,
            );
            rotateKeyOnFailure(req.session, "openai");
          }
        }
      }

      if (!fallbackAttempted) {
        attemptErrors.push(`${selectedModel} (${response.status}): ${details}`);

        if (response.status === 400 || response.status === 404) {
          invalidateSambaNovaModelCache();
        }

        if (response.status === 401 || response.status === 429) {
          rotateKeyOnFailure(req.session, "openai");
        }
      }
    } catch (error) {
      const details =
        error instanceof Error ? error.message : "Unknown SambaNova error";
      attemptErrors.push(`${selectedModel}: ${compactText(details)}`);
      rotateKeyOnFailure(req.session, "openai");
    }
  }

  return res.status(503).json({
    error: "All SambaNova API keys/models failed",
    details: compactText(attemptErrors.join(" | "), 500),
    success: false,
  });
});

// Proxy endpoint for FastRouter (Anthropic Claude) API
app.post("/api/proxy/fastrouter", authenticateSession, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });

  const keyData = getNextKey(req.session, "fastrouter", "FASTROUTER_API_KEY");
  if (!keyData)
    return res.status(503).json({ error: "No FastRouter API keys available" });

  const models = [
    "anthropic/claude-3-7-sonnet-20250219",
    "anthropic/claude-sonnet-4-20250514",
    "anthropic/claude-opus-4.5",
  ];
  const selectedModel = models[Math.floor(Date.now() / 1000) % models.length];

  try {
    const response = await fetch(
      "https://go.fastrouter.ai/api/v1/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${keyData.key}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: selectedModel,
          messages: [
            {
              role: "system",
              content:
                "You are Claude, an AI assistant by Anthropic. Be helpful and honest.",
            },
            { role: "user", content: message },
          ],
          max_tokens: 2048,
          temperature: 0.7,
        }),
      },
    );

    if (!response.ok) {
      if (response.status === 429 || response.status === 401)
        rotateKeyOnFailure(req.session, "fastrouter");
      return res
        .status(response.status)
        .json({ error: "FastRouter API error", status: response.status });
    }

    const data = await response.json();
    res.json({
      content: data.choices?.[0]?.message?.content || "",
      model: selectedModel,
      source: "fastrouter",
      success: true,
    });
  } catch {
    res
      .status(500)
      .json({ error: "Failed to call FastRouter API", success: false });
  }
});

// Proxy endpoint for FastRouter Image Generation / Editing API
app.post("/api/proxy/image-generate", authenticateSession, async (req, res) => {
  const { prompt, model, image } = req.body;
  if (!prompt) return res.status(400).json({ error: "Prompt required" });

  const keyData = getNextKey(req.session, "fastrouter", "FASTROUTER_API_KEY");
  if (!keyData)
    return res.status(503).json({ error: "No FastRouter API keys available" });

  const isEditRequest = !!image;
  const imageModel = model || (isEditRequest ? "openai/dall-e-2" : "openai/dall-e-3");

  try {
    let response;

    if (isEditRequest) {
      const imageData = parseBase64Image(image);
      if (imageData.error) {
        return res.status(400).json({ error: imageData.error });
      }

      const imageBuffer = Buffer.from(imageData.base64Data, "base64");
      if (!imageBuffer.length) {
        return res.status(400).json({ error: "Invalid image data" });
      }
      const formData = new FormData();
      formData.append("model", imageModel);
      formData.append("prompt", prompt);
      formData.append("n", "1");
      formData.append("size", "1024x1024");
      formData.append(
        "image",
        imageBuffer,
        {
          filename: "image.png",
          contentType: imageData.mimeType,
          knownLength: imageBuffer.length,
        },
      );

      let contentLength;
      try {
        contentLength = await new Promise((resolve, reject) => {
          formData.getLength((err, length) => {
            if (err) reject(err);
            else resolve(Number(length));
          });
        });
      } catch (error) {
        return res.status(500).json({
          error: "Failed to calculate image size",
          details: error instanceof Error ? error.message : String(error),
          success: false,
        });
      }

      const formHeaders = formData.getHeaders();
      if (!Number.isFinite(contentLength)) {
        return res.status(500).json({
          error: "Failed to calculate image size",
          details: "Invalid content length for image payload",
          success: false,
        });
      }

      const requestHeaders = {
        Authorization: `Bearer ${keyData.key}`,
        ...formHeaders,
        "Content-Length": String(contentLength),
      };

      let primaryError = null;
      try {
        response = await fetch(
          "https://go.fastrouter.ai/api/v1/images/edits",
          {
            method: "POST",
            headers: requestHeaders,
            body: formData,
            duplex: "half",
          },
        );
      } catch (error) {
        primaryError = error;
      }

      if (!response) {
        const fallbackBody = formData.getBuffer();
        try {
          response = await fetch(
            "https://go.fastrouter.ai/api/v1/images/edits",
            {
              method: "POST",
              headers: {
                Authorization: `Bearer ${keyData.key}`,
                ...formHeaders,
                "Content-Length": String(fallbackBody.length),
              },
              body: fallbackBody,
            },
          );
        } catch (fallbackError) {
          if (fallbackError instanceof Error) {
            fallbackError.cause = primaryError;
          }
          throw fallbackError;
        }
      }
    } else {
      response = await fetch(
        "https://go.fastrouter.ai/api/v1/images/generations",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${keyData.key}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: imageModel,
            prompt,
            n: 1,
            size: "1024x1024",
          }),
        },
      );
    }

    if (!response.ok) {
      if (response.status === 429 || response.status === 401)
        rotateKeyOnFailure(req.session, "fastrouter");
      const errorText = await response.text();
      return res.status(response.status).json({
        error: "Image generation failed",
        status: response.status,
        details: errorText,
        success: false,
      });
    }

    const data = await response.json();
    let imageUrl = data.data?.[0]?.url;
    const b64Json = data.data?.[0]?.b64_json;

    if (b64Json && !imageUrl) imageUrl = `data:image/png;base64,${b64Json}`;

    res.json({
      success: true,
      imageUrl,
      model: imageModel,
      source: "fastrouter",
    });
  } catch (error) {
    const details = error instanceof Error ? error.message : String(error);
    const cause =
      error instanceof Error && error.cause
        ? error.cause instanceof Error
          ? error.cause.message
          : String(error.cause)
        : undefined;
    console.error("Image generation error:", error);
    res.status(500).json({
      error: "Failed to generate image",
      details,
      cause,
      success: false,
    });
  }
});

// Initialize key cache before starting server
initializeKeyCache();

app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
  console.log("CORS allowed origins:", Array.from(allowedOrigins));
  console.log("Primary frontend URL:", primaryFrontendUrl);

  console.log("Configured services:");

  const groqKeys = extractKeys("GROQ_API_KEY");
  const geminiKeys = extractKeys("GOOGLE_API_KEY");
  const openaiKeys = getOpenAICompatibleKeys();
  const openrouterKeys = extractKeys("OPENROUTER_API_KEY");
  const githubKeys = extractKeys("GITHUB_TOKEN");
  const cohereKeys = extractKeys("COHERE_API_KEY");
  const xaiKeys = extractKeys("XAI_API_KEY");
  const fastrouterKeys = extractKeys("FASTROUTER_API_KEY");

  console.log("- Groq:", groqKeys.length, "keys");
  console.log("- Gemini:", geminiKeys.length, "keys");
  console.log("- OpenAI:", openaiKeys.length, "keys");
  console.log("- OpenRouter:", openrouterKeys.length, "keys");
  console.log("- GitHub:", githubKeys.length, "keys");
  console.log("- Cohere:", cohereKeys.length, "keys");
  console.log("- XAI:", xaiKeys.length, "keys");
  console.log("- FastRouter:", fastrouterKeys.length, "keys");

  const totalKeys =
    groqKeys.length +
    geminiKeys.length +
    openaiKeys.length +
    openrouterKeys.length +
    githubKeys.length +
    cohereKeys.length +
    xaiKeys.length +
    fastrouterKeys.length;

  console.log("Total API keys configured:", totalKeys);

  if (totalKeys === 0) {
    console.warn("\n⚠️  WARNING: No API keys found!");
    console.warn(
      "Please ensure your .env.local or .env file contains API keys.",
    );
    console.warn('Example: GROQ_API_KEY1="your-key-here"');
  }
});
