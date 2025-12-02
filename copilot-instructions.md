# AWSAP - Copilot Instructions for AI Agents

**Project**: Advanced Web Security Analysis Platform (AWSAP)  
**Type**: Full-Stack React + Node.js Security Scanner  
**Version**: 1.0.0  
**AI Edition**: Guidelines for Copilot/Cursor/Claude

---

## 🎯 Big Picture Architecture

AWSAP is a **dockerized web security scanning platform** with a React frontend and Node.js backend. It performs passive/active vulnerability scanning with AI-powered analysis.

### System Design
```
┌─────────────────────────────────────────┐
│      Frontend (React 18)                │
│  - SPA hosted in nginx container        │
│  - Tailwind UI with lucide icons        │
│  - Real-time scan progress polling      │
│  - Vulnerability visualization          │
└────────────┬────────────────────────────┘
             │ REST API calls
             ↓
┌─────────────────────────────────────────┐
│  Backend (Node.js/Express)              │
│  - API endpoints for scan orchestration │
│  - SecurityScanner class (passive/active)│
│  - AIAnalysisEngine (ML pattern matching)│
│  - In-memory scan database              │
└────────────┬────────────────────────────┘
             │
       Docker Compose
       (prod deployment)
```

### Key Components

**Frontend** (`frontend/src/`):
- `App.js`: Main React component with 5 tabs (dashboard, scanner, vulnerabilities, ai-analysis, history)
- Uses lucide-react icons for UI
- State managed via React hooks (`useState`, `useEffect`)
- Real-time polling to `/api/scan/status/:scanId` (1s interval)

**Backend** (`backend/Server.js`):
- `SecurityScanner`: Orchestrates passive recon (DNS, fingerprinting, crawling) + active scanning (SQLi, XSS, header checks)
- `AIAnalysisEngine`: Simulates ML models for vulnerability correlation, pattern recognition, anomaly detection
- `/api/scan/start`: Initiates async scan, returns `scanId`
- `/api/scan/status/:scanId`: Returns progress (0-100%, phase name)
- `/api/scan/results/:scanId`: Returns detailed results with AI analysis

**Docker Setup** (`docker-compose.yml`):
- Frontend service: nginx container on port 3000
- Backend service: Node.js on port 5000
- `depends_on` ensures backend starts first

---

## 🔧 Critical Developer Workflows

### Local Development
```bash
# Backend
cd backend
npm install
npm start  # Runs on port 5000

# Frontend (separate terminal)
cd frontend
npm install
npm start  # Runs on port 3000, proxies /api to localhost:5000
```

### Docker Deployment
```bash
docker-compose up --build
# Frontend: http://localhost:3000
# Backend: http://localhost:5000/api/health
```

### Debugging Scans
- Backend logs scan progress via `updateProgress(progressCallback, percentage, phaseName)`
- Frontend polls every 1s for status updates
- Common issues: URL validation, CORS errors, timeout handling

---

## 📊 Project-Specific Patterns

### 1. Async Scan Pattern
**Location**: `backend/Server.js` line ~360 (POST /scan/start)

Scans are **asynchronous** with progress tracking:
```javascript
// Backend initiates scan WITHOUT awaiting
scanner.scan(progressCallback).then(results => {
  // Store results when complete
  scanDatabase.set(scanId, results);
  scanQueue.set(scanId, { status: 'complete', progress: 100 });
});

// Frontend polls for updates
setInterval(() => {
  fetch(`/api/scan/status/${scanId}`) // Check progress
}, 1000);
```

**Key files**: 
- `backend/Server.js`: Lines 360-420 (POST /scan/start)
- `frontend/App.js`: Lines 40-65 (useEffect polling)

### 2. Vulnerability Detection Pipeline
**Location**: `backend/Server.js` SecurityScanner class

Pattern: **signature-based detection** with HTTP response analysis
```javascript
// Test target with payload
// Check response for error patterns or payload reflection
// If match → add to vulnerabilities array
```

**Detections**:
- SQL Injection: Regex error patterns (e.g., `/SQL syntax.*MySQL/i`)
- XSS: Payload reflection check (`response.data.includes(payload)`)
- Command Injection: Time-based detection (sleep 5s timeout)
- Security Headers: Missing header checks

**Extends to**: Add new signatures to `vulnerabilitySignatures` object

### 3. AI Analysis Simulation
**Location**: `backend/Server.js` AIAnalysisEngine class (~Lines 20-150)

Pattern: **Multi-stage inference** mimicking real ML models:
```javascript
// Stage 1: Correlate vulnerabilities into attack chains
correlateVulnerabilities(vulnerabilities) → chains[]

// Stage 2: Pattern recognition (NLP-like analysis)
recognizePatterns(scanData) → { injectionPatterns, authFlaws, codeQuality, anomalies }

// Stage 3: Anomaly detection (statistical outliers)
detectAnomalies(scanData) → { detected, confidence, pattern }

// Stage 4: Generate recommendations
generateRecommendations(vulns, patterns) → recommendations[]
```

**Important**: Currently simulated with hardcoded logic and `Math.random()`. To make real:
- Replace with actual ML model calls (TensorFlow.js, API)
- Train on real vulnerability datasets

---

## 🔌 Integration Points & Data Flows

### Frontend → Backend Contract
**HTTP Endpoints**:
- `POST /api/scan/start` (body: `{targetUrl, config}`) → `{scanId}`
- `GET /api/scan/status/:scanId` → `{status, progress, phase, error}`
- `GET /api/scan/results/:scanId` → Full scan results JSON
- `GET /api/scans` → Scan history array
- `GET /api/scan/export/:scanId` → JSON file download

**CORS**: Enabled via `cors()` middleware (all origins allowed)

### Scan Config Schema
```javascript
{
  passiveRecon: boolean,      // DNS, fingerprinting, crawling
  activeScanning: boolean,    // SQLi, XSS, command injection tests
  aiAnalysis: boolean,        // Enable AI post-processing
  deepCrawl: boolean,         // Crawl up to 10 pages (hardcoded)
  aggressiveness: 'low' | 'medium' | 'high'  // UI only (not implemented)
}
```

### Vulnerability Object Schema
```javascript
{
  id: string,              // VULN-{timestamp}-{randomHex}
  type: string,            // 'SQL Injection', 'XSS', etc.
  severity: 'critical' | 'high' | 'medium' | 'low',
  endpoint: string,        // Full URL of vulnerable endpoint
  parameter: string,       // Input field name
  method: 'GET' | 'POST',
  payload: string,         // Test payload used
  confidence: number,      // 0-100%
  evidence: string,        // Why it was flagged
  timestamp: ISO string
}
```

---

## 🛠️ Configuration & Customization

### Environment Variables
**Backend** (`backend/Server.js` Line 14):
```javascript
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';
```

**Frontend** (`frontend/src/App.js` Line 5):
```javascript
const API_BASE_URL = 'http://localhost:5000/api';
// In production, set via env file or build-time substitution
```

### Adding New Vulnerability Types
**File**: `backend/Server.js` Line ~280

1. Add to `vulnerabilitySignatures` object:
```javascript
myCustomVulnerability: {
  payloads: ['payload1', 'payload2'],
  errorPatterns: [/pattern1/i, /pattern2/i],
  name: 'My Custom Vulnerability',
  severity: 'high'
}
```

2. Create test method in `SecurityScanner` class:
```javascript
async testMyVulnerability() {
  // Similar to testSQLInjection()
}
```

3. Call from `activeVulnerabilityScanning()`:
```javascript
await this.testMyVulnerability();
```

### Modifying UI Tabs
**File**: `frontend/App.js` Line ~95

Tabs are in the navigation section. Add new tab:
```javascript
{['dashboard', 'scanner', 'vulnerabilities', 'ai-analysis', 'history', 'new-tab'].map(tab => (...))}
// Add case in main content area:
{activeTab === 'new-tab' && (
  <div>Your new tab content</div>
)}
```

---

## 🚀 Common Tasks & Commands

### Running Full Stack Locally
```bash
# Terminal 1: Backend
cd backend && npm install && npm start

# Terminal 2: Frontend
cd frontend && npm install && npm start
```

### Building Docker Images
```bash
docker-compose build
docker-compose up
```

### Testing Backend API
```bash
curl -X POST http://localhost:5000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"targetUrl":"https://example.com","config":{"passiveRecon":true,"activeScanning":true}}'

# Returns: {"scanId":"abc123...","status":"initiated"}
```

### Debugging
- **Backend logs**: Check console output for scan progress
- **Frontend devtools**: Network tab shows all API calls
- **Database inspection**: Add `console.log(scanDatabase)` in backend

---

## 📋 Code Standards & Patterns

### State Management (Frontend)
- Use React hooks (`useState`, `useEffect`)
- No Redux (keep simple for this project)
- Prop drilling acceptable given component depth

### Error Handling
- Frontend: `try/catch` in fetch calls, alert users
- Backend: Pass errors via `/api/scan/status` or HTTP status codes

### Naming Conventions
- Components: PascalCase (`AWSAP`, `SecurityScanner`)
- Functions/variables: camelCase
- CSS classes: kebab-case with Tailwind semantics

### Code Organization
```
frontend/
├── src/
│   ├── App.js          (main component, 700+ lines - could refactor)
│   ├── App.css         (minimal, mostly Tailwind)
│   └── Index.js        (entry point)
├── public/
│   └── index.html      (root HTML)
└── package.json

backend/
├── Server.js           (monolithic, 700+ lines - 3 classes)
└── package.json
```

---

## 🔐 Security Considerations

### ⚠️ Current Limitations
1. **No authentication** - Anyone can access API
2. **No input sanitization** - User URLs not validated beyond URL format
3. **No rate limiting** - Possible DoS via repeated scans
4. **Simulated AI** - Not using real ML models, just heuristics
5. **CORS wide open** - `cors()` allows all origins

### Production Hardening Checklist
- [ ] Add JWT auth middleware
- [ ] Implement rate limiting (`express-rate-limit`)
- [ ] Validate/sanitize all inputs
- [ ] Replace simulated AI with real models
- [ ] Add CORS whitelist instead of `*`
- [ ] Use HTTPS in docker-compose
- [ ] Add request logging/monitoring
- [ ] Implement scan timeout limits

### Responsible Use
- **Only scan systems you own/have permission for**
- AWSAP is for authorized penetration testing
- Do not use for unauthorized access attempts

---

## 📖 References & Related Code

### Frontend (React)
- `App.js`: 
  - State setup (Line ~20-35)
  - Polling logic (Line ~40-65)
  - Tab rendering (Line ~95-105)
  - Vulnerability severity colors (Line ~168-175)

### Backend (Node.js)
- `Server.js`:
  - API routes (Line ~360+)
  - SecurityScanner class (Line ~180)
  - AIAnalysisEngine class (Line ~20)
  - Vulnerability signatures (Line ~270)

### Docker
- `docker-compose.yml`: Service definitions
- `frontend/Dockerfile`: Multi-stage React build
- `backend/Dockerfile`: Node.js runtime
- `frontend/nginx.conf`: SPA routing

---

## ✅ When Modifying Code

**Always consider**:
1. Does this change affect the scan pipeline or API contract?
2. Do both frontend and backend handle the change?
3. Is error handling implemented?
4. Does Docker still build cleanly?
5. Do all 5 UI tabs still work?

**Before committing**:
```bash
# Backend: Test API
curl http://localhost:5000/api/health

# Frontend: Run once through all tabs
npm start  # Click all 5 tabs, run a scan

# Docker: Full build
docker-compose down && docker-compose up --build
```

---

**Last Updated**: October 2025  
**Maintainer**: AWSAP Team
