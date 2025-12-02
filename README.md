# 🛡️ AWSAP - Advanced Web Security Analysis Platform

> AI-powered web security scanner with real-time vulnerability detection, passive reconnaissance, and intelligent attack chain analysis.

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/sujal/AWSAP)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![React](https://img.shields.io/badge/react-18.2.0-61dafb.svg)](https://react.dev)
[![Node.js](https://img.shields.io/badge/node.js-16+-339933.svg)](https://nodejs.org)

## 📋 Features

### 🔍 Reconnaissance & Discovery
- **Passive Reconnaissance**: DNS lookups, technology fingerprinting, header analysis
- **Web Crawling**: Automatic endpoint discovery with form and input detection
- **Technology Stack Detection**: Identify servers, frameworks, and libraries

### 🎯 Vulnerability Scanning
- **SQL Injection Detection**: Pattern-based error analysis and payload testing
- **Cross-Site Scripting (XSS)**: Payload reflection detection
- **Command Injection**: Time-based detection with sleep payloads
- **Security Header Analysis**: Detect missing/misconfigured security headers
- **Extensible Signature System**: Easy to add new vulnerability types

### 🧠 AI-Powered Analysis
- **Vulnerability Correlation**: Identify multi-step attack chains
- **Pattern Recognition**: Detect injection patterns, authorization flaws, code quality issues
- **Anomaly Detection**: Transformer-based unusual behavior identification
- **Smart Recommendations**: Context-aware remediation guidance

### 📊 Beautiful Dashboard
- **Real-time Scan Progress**: Live phase and percentage updates
- **Vulnerability Visualization**: Severity-based color coding and filtering
- **Detailed Reports**: Exportable JSON reports with evidence and remediation
- **Scan History**: Track previous assessments and compare results

---

## 🚀 Quick Start

### Prerequisites
- **Docker & Docker Compose** (recommended for production)
- **Node.js 16+** and npm (for local development)
- **Modern web browser** (Chrome, Firefox, Edge, Safari)

### Docker Deployment (Recommended)
```bash
# Clone the repository
git clone <repo-url>
cd AWSAP

# Build and run
docker-compose up --build

# Access the application
# 🌐 Main URL: http://localhost:3000  ← USE THIS ONE!
# The frontend will automatically connect to the backend via nginx proxy
# 
# Note: Don't access http://localhost:5000 directly - that's the raw API
```

> **⚠️ Important**: Always access the application via **port 3000** (frontend).  
> Port 5000 is for the backend API and is proxied through nginx automatically.

### Visual Preview

Below are suggested visual elements to make this repository look great on GitHub. Replace the example image paths with actual screenshots you capture from the running app. Store screenshots under `docs/screenshots/` or `frontend/public/assets/` and commit them alongside the README for best results.

- **Dashboard (example):**

  ![AWSAP Dashboard](docs/screenshots/dashboard.png)

- **Terminal (PowerShell) - Quick run example:**

  ```powershell
  # Start backend and frontend (Docker)
  PS> cd C:\Path\To\AWSAP; docker-compose up --build

  # Quick health check
  PS> curl http://localhost:5000/api/health
  {
    "status": "operational",
    "version": "1.0.0",
    "timestamp": "2025-10-29T..."
  }

  # Start a scan via curl (example)
  PS> curl -X POST http://localhost:5000/api/scan/start -H 'Content-Type: application/json' -d '{"targetUrl":"https://example.com","config":{"passiveRecon":true,"activeScanning":true}}'
  { "scanId": "a1b2c3d4...", "status": "initiated" }

  # Poll status (sample)
  PS> curl http://localhost:5000/api/scan/status/a1b2c3d4...
  { "status": "running", "progress": 45, "phase": "Active Scanning", "error": null }

  # Simple ASCII progress snippet (for README preview)
  [#####........] 45% Active Scanning
  ```

- **How to add real screenshots**:

  1. Run the app locally or in Docker and open the UI at `http://localhost:3000`.
  2. Take screenshots (dashboard, scanner, vulnerability view, terminal).
  3. Place images in `docs/screenshots/` (create this folder) or `frontend/public/assets/`.
  4. Use this markdown to embed: `![Alt text](docs/screenshots/your-file.png)`.

> Tip: Keep screenshot file names short and lowercase, e.g. `dashboard.png`, `scanner.png`, `terminal.png`.

### Local Development Setup
```bash
# Terminal 1: Backend
cd backend
npm install
npm start
# Backend running on http://localhost:5000

# Terminal 2: Frontend (in another terminal)
cd frontend
npm install
npm start
# Frontend running on http://localhost:3000
```

---

## 📖 Usage Guide

### Starting a Security Scan

1. **Navigate to Scanner Tab**
   - Enter target URL (e.g., `https://example.com`)
   - Configure scan options:
     - ✓ Passive Recon (DNS, fingerprinting)
     - ✓ Active Scanning (vulnerability tests)
     - ✓ AI Analysis (pattern detection)
   - Select aggressiveness level

2. **Monitor Progress**
   - Real-time phase tracking (Crawling → Scanning → Analysis)
   - Progress bar shows overall scan completion
   - View discovered endpoints and technologies

3. **Review Results**
   - Dashboard shows vulnerability counts by severity
   - Detected technologies with version info
   - Scan metadata (duration, requests, IP info)

### Analyzing Vulnerabilities

- **Click any vulnerability** for detailed analysis
- **View location**: Endpoint URL, parameter name, HTTP method
- **Evidence**: Why AWSAP flagged this issue
- **Impact**: Business and technical consequences
- **Remediation**: Step-by-step fix instructions

### AI-Powered Analysis

#### Vulnerability Correlation
Identifies multi-step attack chains. Example:
```
SQL Injection → Database Access
→ Authentication Bypass → Privilege Escalation
Risk Score: 9.4/10 (Critical)
```

#### Pattern Recognition
- **Injection Patterns**: SQL, Command, LDAP detection confidence
- **Authorization Flaws**: IDOR, missing access control
- **Code Quality**: Hardcoded credentials, weak crypto
- **Anomalies**: Unusual response times, error patterns

#### Anomaly Detection
Novel patterns that don't match known vulnerabilities. Requires manual review.

### Exporting Reports

Click **Export** button to download:
```json
{
  "target": "https://example.com",
  "scanDate": "2025-10-29T...",
  "totalVulnerabilities": 7,
  "vulnerabilities": [...],
  "aiAnalysis": {
    "vulnerabilityChains": [...],
    "patterns": {...},
    "recommendations": [...]
  }
}
```

---

## 🏗️ Project Structure

```
AWSAP/
├── docker-compose.yml          # Multi-container orchestration
├── .github/
│   └── copilot-instructions.md # AI agent guidelines
├── frontend/                   # React 18 UI
│   ├── public/
│   │   └── index.html          # Root HTML
│   ├── src/
│   │   ├── App.js              # Main component (5 tabs)
│   │   ├── Index.js            # React entry point
│   │   └── Index.css           # Tailwind + custom styles
│   ├── package.json            # Frontend dependencies
│   ├── tailwind.config.js      # Tailwind CSS config
│   ├── postcss.config.js       # PostCSS plugins
│   ├── nginx.conf              # SPA routing config
│   └── Dockerfile              # Multi-stage build
├── backend/                    # Node.js/Express API
│   ├── Server.js               # Main application (700+ lines)
│   ├── package.json            # Backend dependencies
│   └── Dockerfile              # Node.js runtime
└── README.md                   # This file
```

---

## 🔧 Architecture

### Frontend Stack
- **React 18**: Modern component-based UI
- **Tailwind CSS**: Utility-first styling
- **lucide-react**: Beautiful icon library
- **Fetch API**: HTTP requests to backend

### Backend Stack
- **Express.js**: REST API framework
- **Axios**: HTTP client for external requests
- **Cheerio**: HTML parsing for web crawling
- **Node.js DNS**: Domain resolution

### Deployment
- **Docker Compose**: Multi-container orchestration
- **Nginx**: Frontend hosting with SPA routing
- **Node.js Alpine**: Lightweight backend container

---

## 🔌 API Reference

### Start Scan
```http
POST /api/scan/start
Content-Type: application/json

{
  "targetUrl": "https://example.com",
  "config": {
    "passiveRecon": true,
    "activeScanning": true,
    "aiAnalysis": true,
    "deepCrawl": true,
    "aggressiveness": "medium"
  }
}

Response:
{
  "scanId": "a1b2c3d4...",
  "status": "initiated"
}
```

### Get Scan Status
```http
GET /api/scan/status/{scanId}

Response:
{
  "status": "running|complete|error",
  "progress": 45,
  "phase": "Active Scanning",
  "error": null
}
```

### Get Scan Results
```http
GET /api/scan/results/{scanId}

Response:
{
  "target": "https://example.com",
  "scanDate": "2025-10-29T...",
  "totalVulnerabilities": 7,
  "criticalCount": 1,
  "highCount": 2,
  "mediumCount": 3,
  "lowCount": 1,
  "riskScore": 67,
  "vulnerabilities": [...],
  "aiAnalysis": {...}
}
```

### List Scan History
```http
GET /api/scans

Response:
[
  {
    "scanId": "abc...",
    "target": "https://example.com",
    "scanDate": "2025-10-29T...",
    "totalVulnerabilities": 7,
    "riskScore": 67
  }
]
```

### Export Report
```http
GET /api/scan/export/{scanId}

Response: JSON file download
```

### Health Check
```http
GET /api/health

Response:
{
  "status": "operational",
  "version": "1.0.0",
  "timestamp": "2025-10-29T..."
}
```

---

## 🛠️ Development Guide

### Adding New Vulnerability Type

1. **Define Signature** (`backend/Server.js`, line ~280):
```javascript
vulnerabilitySignatures.myVulnerability = {
  payloads: ['payload1', 'payload2'],
  errorPatterns: [/pattern/i],
  name: 'My Vulnerability',
  severity: 'high'
};
```

2. **Create Test Method**:
```javascript
async testMyVulnerability() {
  for (const endpoint of this.discoveredEndpoints) {
    // Test logic
    if (isVulnerable) {
      this.vulnerabilities.push({
        id: `VULN-${Date.now()}-${randomHex}`,
        type: 'My Vulnerability',
        // ... other fields
      });
    }
  }
}
```

3. **Register in Scan Pipeline**:
```javascript
async activeVulnerabilityScanning(progressCallback) {
  // ... existing tests
  await this.testMyVulnerability();
}
```

### Extending AI Analysis

**File**: `backend/Server.js`, `AIAnalysisEngine` class

- `correlateVulnerabilities()`: Add new attack chains
- `recognizePatterns()`: Add pattern detection logic
- `detectAnomalies()`: Improve anomaly detection
- `generateRecommendations()`: Custom recommendations

### Running Tests

```bash
# Backend API test
curl http://localhost:5000/api/health

# Frontend build
cd frontend && npm run build

# Docker test
docker-compose up && curl http://localhost:3000
```

---

## 🔐 Security Disclaimer

### ⚠️ Important Legal Notice

**AWSAP is designed EXCLUSIVELY for authorized security testing.** Users must:

✅ **Only scan systems you own or have written permission to test**  
✅ **Comply with all local, state, and federal laws**  
✅ **Obtain explicit written authorization before testing**  
✅ **Respect the scope and boundaries defined in authorization**

❌ **DO NOT scan systems without permission**  
❌ **DO NOT use for malicious purposes**  
❌ **DO NOT distribute scan results without consent**

### Current Limitations

- **No authentication**: Anyone accessing the app can run scans
- **Simulated AI**: Not using real ML models (for now)
- **CORS wide open**: Consider restricting in production
- **No rate limiting**: Possible DoS attacks
- **No input validation**: Limited URL format checking

### Production Hardening

```javascript
// Add authentication middleware
const authMiddleware = (req, res, next) => { /* ... */ };
app.use('/api', authMiddleware);

// Add rate limiting
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api/scan/start', limiter);

// Restrict CORS
app.use(cors({ origin: 'https://yourdomain.com' }));
```

---

## 📝 Configuration

### Environment Variables

Create `.env` file:
```env
# Backend
NODE_ENV=production
PORT=5000
LOG_LEVEL=info

# Frontend
REACT_APP_API_URL=http://localhost:5000/api
```

### Docker Compose Override

```yaml
# docker-compose.override.yml (local dev)
version: '3.8'
services:
  backend:
    environment:
      - NODE_ENV=development
      - LOG_LEVEL=debug
```

---

## 🐛 Troubleshooting

### Frontend can't connect to backend
- Check backend is running: `curl http://localhost:5000/api/health`
- Verify CORS is enabled
- Check network tab in browser devtools

### Scan fails silently
- Check backend logs for errors
- Verify target URL is accessible
- Try with public website (e.g., `https://scanme.nmap.org`)

### Docker build fails
```bash
# Clean up
docker-compose down
docker system prune -a

# Rebuild
docker-compose up --build
```

### High CPU usage during scan
- Reduce `maxPages` in `crawl()` method
- Disable `activeScanning` option
- Implement timeout limits

---

## 📚 Learn More

- [React Documentation](https://react.dev)
- [Tailwind CSS](https://tailwindcss.com)
- [Express.js](https://expressjs.com)
- [OWASP Top 10](https://owasp.org/www-project-top-ten)
- [Docker Compose](https://docs.docker.com/compose)

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**AWSAP Team** - Advanced Web Security Analysis Platform

- 🌐 [GitHub](https://github.com/sujal/AWSAP)
- 📧 [Contact](mailto:info@awsap.dev)

---

## 🙏 Acknowledgments

- React team for amazing frontend framework
- Express.js for robust backend framework
- Tailwind CSS for beautiful utility-first styling
- OWASP for security guidance and standards

---

## 📊 Current Status

- ✅ Core scanning engine implemented
- ✅ Frontend UI complete (5 tabs)
- ✅ AI analysis simulation ready
- ✅ Docker setup functional
- ⏳ Real ML model integration (planned)
- ⏳ Authentication system (planned)
- ⏳ Database persistence (planned)
- ⏳ Advanced reporting (planned)

---

**Latest Update**: October 29, 2025  
**Version**: 1.0.0  
**Status**: Production Ready (with cautions noted above)
