---
description: Repository Information Overview
alwaysApply: true
---

# Repository Information Overview

## Repository Summary
AWSAP (Advanced Web Security Analysis Platform) is a comprehensive web security analysis and vulnerability scanning platform with AI-powered analysis capabilities. The platform includes a Node.js backend server that performs real-time security scanning and a React frontend for user interaction and visualization of security vulnerabilities.

## Repository Structure
The repository is organized as a full-stack web application with separate frontend and backend components:
- **backend/**: Express.js server handling security scanning logic, API endpoints, and data processing
- **frontend/src/**: React-based user interface with components for dashboard, scanner, vulnerability analysis, and reporting

### Main Repository Components
- **Backend Server (Node.js/Express)**: Handles HTTP requests, coordinates security scans, processes vulnerability detection, performs AI analysis, and manages scan history
- **Frontend UI (React)**: Provides interactive dashboard, scan configuration interface, vulnerability display, AI analysis results, and report export functionality

## Projects

### Backend Server (Express.js)
**Configuration File**: backend/package.json

#### Language & Runtime
**Language**: JavaScript (Node.js)
**Runtime**: Node.js
**Version**: Latest compatible with dependencies
**Build System**: npm
**Package Manager**: npm

#### Dependencies
**Main Dependencies**:
- **express** (^4.18.2): Web application framework for building HTTP APIs
- **cors** (^2.8.5): Cross-Origin Resource Sharing middleware for browser-based frontend communication
- **axios** (^1.6.0): HTTP client for making requests and web scraping
- **cheerio** (^1.0.0-rc.12): jQuery-like library for HTML parsing and DOM manipulation

**Development Dependencies**:
- **nodemon** (^3.0.1): Auto-restart development server on file changes

#### Build & Installation
`ash
# Install dependencies
npm install

# Start production server
npm start

# Start development server with auto-reload
npm run dev
`

#### Application Structure
**Main Entry Point**: backend/Server.js (762 lines)
- REST API endpoints for security scanning operations
- In-memory database for storing scan results and scan queue
- Vulnerability signature database with SQL Injection, XSS, Command Injection, Path Traversal, and Open Redirect detection
- AI Analysis Engine for correlating vulnerabilities and detecting attack chains
- Scan status polling and result retrieval endpoints
- Report export functionality

**Key API Routes**:
- POST /api/scan/start: Initiate new security scan with configuration
- GET /api/scan/status/{scanId}: Check real-time scan progress
- GET /api/scan/results/{scanId}: Retrieve completed scan results
- GET /api/scans: Fetch scan history
- GET /api/scan/export/{scanId}: Export scan report

### Frontend UI (React)
**Configuration Files**: frontend/src/App.js, frontend/src/Index.js

#### Language & Runtime
**Language**: JavaScript (React/JSX)
**Version**: React 18+ (from imports)
**Build System**: Bundled with backend or separate build process
**Package Manager**: npm (assumed, coordinates with backend)

#### Dependencies
**Main Dependencies** (from imports in App.js):
- **react**: UI library with hooks (useState, useEffect)
- **lucide-react**: Icon library for security-related UI elements

#### Application Structure
**Main Component**: frontend/src/App.js (1215 lines)
- Core AWSAP component with tab-based navigation
- Dashboard view displaying vulnerability statistics and risk scores
- Scanner interface for initiating new scans with configuration options
- Vulnerabilities tab with detailed vulnerability analysis and remediation guidance
- AI Analysis tab showing correlations and attack chain detection
- History tab for reviewing previous scans
- Real-time scan progress tracking with polling mechanism
- Report export functionality
- Severity classification system (critical, high, medium, low)

**Styling**: frontend/src/App.css (minimal, likely uses Tailwind CSS classes in JSX)

**Key Features**:
- Real-time scan status updates via polling
- Vulnerability severity color-coding
- Detailed vulnerability descriptions including impact and remediation steps
- AI-powered analysis of vulnerability chains
- Scan history management and previous scan loading
- JSON report generation and download

#### Build & Installation
`ash
# Install React dependencies (if separate from backend)
npm install

# Development build (usually served by backend dev server)
npm start

# Or run with backend
cd backend && npm run dev
`

---

**Total Token Count**: ~1000 tokens  
**Last Updated**: Repository analysis complete  
**Architecture Pattern**: Full-stack monorepo with backend API and React frontend
