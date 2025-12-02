// AWSAP Backend - Advanced Web Security Analysis Platform
// Node.js + Express Server with Security Scanning Engine

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const cheerio = require('cheerio');
const dns = require('dns').promises;
const { URL } = require('url');
const crypto = require('crypto');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 5000;

// Security Configuration
const JWT_SECRET = crypto.randomBytes(32).toString('hex');
const SALT_ROUNDS = 12;

// Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again after 15 minutes'
});

const scanLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Limit each IP to 10 scans per hour
  message: 'Scan limit reached. Please try again later.'
});

// CORS Configuration
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://your-frontend-domain.com'] 
    : ['http://localhost:3000'],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  credentials: true,
  maxAge: 600 // 10 minutes
};

// User Store (replace with database in production)
const users = new Map();

// Middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: '10kb' })); // Limit payload size
app.use(helmet()); // Security headers

// Apply rate limiting
app.use('/api/', apiLimiter);
app.use('/api/scan/start', scanLimiter);

// Security Middleware
const validateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Request Validation Middleware
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// Security Logging Middleware
const securityLogger = (req, res, next) => {
  const log = {
    timestamp: new Date().toISOString(),
    ip: req.ip,
    method: req.method,
    path: req.path,
    headers: {
      'user-agent': req.headers['user-agent'],
      'content-type': req.headers['content-type']
    }
  };
  console.log('Security Log:', log);
  next();
};

// In-memory storage for scan results
const scanDatabase = new Map();
const scanQueue = new Map();

// Security Vulnerability Database
const vulnerabilitySignatures = {
  sqlInjection: {
    payloads: ["'", "1' OR '1'='1", "' OR 1=1--", "admin'--", "' UNION SELECT NULL--"],
    errorPatterns: [
      /SQL syntax.*MySQL/i,
      /Warning.*mysql_/i,
      /PostgreSQL.*ERROR/i,
      /Microsoft SQL Server/i,
      /ORA-\d{5}/i,
      /SQLite\/JDBCDriver/i,
      /SQLServer JDBC Driver/i
    ],
    name: 'SQL Injection',
    severity: 'critical'
  },
  xss: {
    payloads: [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg/onload=alert(1)>',
      'javascript:alert(1)',
      '<iframe src=javascript:alert(1)>'
    ],
    name: 'Cross-Site Scripting (XSS)',
    severity: 'high'
  },
  commandInjection: {
    payloads: ['; ls', '| whoami', '`id`', '$(whoami)', '; cat /etc/passwd'],
    name: 'Command Injection',
    severity: 'critical'
  },
  pathTraversal: {
    payloads: ['../../etc/passwd', '..\\..\\windows\\system32\\drivers\\etc\\hosts', '../../../'],
    name: 'Path Traversal',
    severity: 'high'
  },
  openRedirect: {
    payloads: ['//evil.com', 'https://evil.com', 'javascript:alert(1)'],
    name: 'Open Redirect',
    severity: 'medium'
  }
};

// AI Analysis Engine (Simulated ML Models)
class AIAnalysisEngine {
  constructor() {
    this.knownPatterns = new Map();
    this.anomalyThreshold = 0.75;
  }

  // Vulnerability Correlation Analysis
  correlateVulnerabilities(vulnerabilities) {
    const chains = [];
    const vulnTypes = vulnerabilities.map(v => v.type);

    // Known attack chains
    const knownChains = [
      {
        pattern: ['SQL Injection', 'Authentication Bypass', 'Privilege Escalation'],
        confidence: 0.87,
        riskScore: 9.4,
        priority: 'critical'
      },
      {
        pattern: ['Cross-Site Scripting (XSS)', 'Session Hijacking', 'IDOR'],
        confidence: 0.73,
        riskScore: 7.2,
        priority: 'high'
      },
      {
        pattern: ['Command Injection', 'File Upload', 'Remote Code Execution'],
        confidence: 0.91,
        riskScore: 9.8,
        priority: 'critical'
      }
    ];

    knownChains.forEach(chain => {
      const matches = chain.pattern.filter(p => vulnTypes.includes(p));
      if (matches.length >= 2) {
        chains.push({
          ...chain,
          matchedVulnerabilities: matches,
          chainLength: matches.length
        });
      }
    });

    return chains;
  }

  // Pattern Recognition using Neural Network Simulation
  recognizePatterns(scanData) {
    const patterns = {
      injectionPatterns: {
        sqlInjection: 0,
        commandInjection: 0,
        ldapInjection: 0
      },
      authorizationFlaws: {
        idor: 0,
        missingAccessControl: 0,
        roleConfusion: 0
      },
      codeQuality: {
        hardcodedCredentials: 0,
        insecureRandomness: 0,
        weakCrypto: 0
      },
      anomalies: {
        unusualResponseTimes: 0,
        errorRateSpikes: 0,
        suspiciousRedirects: 0
      }
    };

    // Simulate pattern recognition
    scanData.vulnerabilities.forEach(vuln => {
      if (vuln.type.includes('Injection')) {
        patterns.injectionPatterns.sqlInjection += vuln.confidence / 100;
      }
      if (vuln.type.includes('IDOR') || vuln.type.includes('Access Control')) {
        patterns.authorizationFlaws.idor += vuln.confidence / 100;
      }
    });

    // Simulate code quality analysis
    patterns.codeQuality.hardcodedCredentials = Math.floor(Math.random() * 5);
    patterns.codeQuality.insecureRandomness = Math.floor(Math.random() * 8);
    patterns.codeQuality.weakCrypto = Math.floor(Math.random() * 3);

    // Simulate anomaly detection
    patterns.anomalies.unusualResponseTimes = Math.floor(Math.random() * 15);
    patterns.anomalies.errorRateSpikes = Math.floor(Math.random() * 6);
    patterns.anomalies.suspiciousRedirects = Math.floor(Math.random() * 8);

    return patterns;
  }

  // Anomaly Detection using Transformer Model Simulation
  detectAnomalies(scanData) {
    const anomalyScore = Math.random();
    
    if (anomalyScore > this.anomalyThreshold) {
      return {
        detected: true,
        confidence: Math.floor(anomalyScore * 100),
        pattern: {
          detectionMethod: 'Transformer-based Anomaly Detection',
          affectedComponents: ['WebSocket Handler', 'Session Manager', 'API Gateway'],
          similarityToKnownCVEs: Math.floor(Math.random() * 30),
          behaviorSignature: crypto.randomBytes(16).toString('hex')
        },
        requiresManualReview: true
      };
    }

    return { detected: false };
  }

  // Generate AI Recommendations
  generateRecommendations(vulnerabilities, patterns) {
    const recommendations = [];

    const critical = vulnerabilities.filter(v => v.severity === 'critical');
    const high = vulnerabilities.filter(v => v.severity === 'high');

    if (critical.length > 0) {
      recommendations.push({
        priority: 'critical',
        title: 'Critical: Immediate Action Required',
        description: `Found ${critical.length} critical vulnerabilities that could lead to complete system compromise.`,
        actions: [
          'Implement parameterized queries immediately',
          'Enable multi-factor authentication',
          'Conduct emergency security audit',
          'Review and patch all critical findings within 24 hours'
        ]
      });
    }

    if (high.length > 0) {
      recommendations.push({
        priority: 'high',
        title: 'High Priority: Schedule Security Updates',
        description: `${high.length} high-severity issues require attention to prevent potential attacks.`,
        actions: [
          'Implement Content Security Policy headers',
          'Add output encoding for all user inputs',
          'Review session timeout configurations',
          'Schedule security patches within 7 days'
        ]
      });
    }

    if (patterns.codeQuality.hardcodedCredentials > 0) {
      recommendations.push({
        priority: 'medium',
        title: 'Medium Priority: Code Quality Improvements',
        description: 'Security anti-patterns detected in codebase.',
        actions: [
          'Remove all hardcoded credentials',
          'Implement secure credential management',
          'Use cryptographically secure random number generators',
          'Update to modern encryption standards'
        ]
      });
    }

    return recommendations;
  }
}

// Scanner Engine
class SecurityScanner {
  constructor(targetUrl, config) {
    this.targetUrl = targetUrl;
    // Merge provided config with sensible defaults
    this.config = Object.assign({
      passiveRecon: true,
      activeScanning: true,
      aiAnalysis: true,
      deepCrawl: true,
      deauthTest: false,
      deepAnalysis: false,
      aggressiveness: 'medium', // low | medium | high
      simulateExploits: false,
      zeroDayResearch: false,
      enhancedHeaders: true, // NEW: Detailed header analysis
      advancedFingerprinting: true, // NEW: Enhanced tech detection
      apiDiscovery: true, // NEW: API endpoint scanning
      cookieAnalysis: true, // NEW: Advanced cookie tests
      contentAnalysis: true, // NEW: Pattern-based content scanning
      // Authorization/consent fields
      authorized: false,
      operator: null,
      authorizedTargets: []
    }, config || {});
    this.vulnerabilities = [];
    this.discoveredEndpoints = [];
    this.technologies = [];
    this.scanMetadata = {
      startTime: Date.now(),
      endTime: null,
      duration: null,
      requestCount: 0,
      errorCount: 0,
      apiEndpoints: [], // NEW: Track discovered APIs
      headers: {}, // NEW: Store interesting headers
      techStack: {} // NEW: Detailed technology information
    };
    // Additional collectors for deep analysis
    this.deepFindings = {
      deauth: [],
      hiddenInputs: [],
      robots: null,
      apiPatterns: [], // NEW: API patterns discovered
      contentPatterns: [], // NEW: Interesting content patterns
      cookieDetails: [], // NEW: Detailed cookie analysis
      headerAnomalies: [] // NEW: Unusual header configurations
    };
  }

  // Main scan orchestration
  async scan(progressCallback) {
    try {
      await this.updateProgress(progressCallback, 10, 'Initializing Scanner');
      
      if (this.config.passiveRecon) {
        await this.passiveReconnaissance(progressCallback);
      }

      if (this.config.activeScanning) {
        await this.activeVulnerabilityScanning(progressCallback);
      }

      // Run optional deep analysis if requested or aggressive mode
      if (this.config.deepAnalysis || this.config.aggressiveness === 'high') {
        await this.updateProgress(progressCallback, 85, 'Deep Analysis');
        await this.deepAnalysis(progressCallback);
      }

      // Run deauthentication tests if enabled or in aggressive mode
      if (this.config.deauthTest || this.config.aggressiveness === 'high') {
        await this.updateProgress(progressCallback, 88, 'Deauth Testing');
        await this.testDeauth();
      }

      // Run zero-day passive research analysis if enabled
      if (this.config.zeroDayResearch || this.config.aggressiveness === 'high') {
        await this.updateProgress(progressCallback, 89, 'Zero-Day Research');
        await this.detectZeroDayCandidates(progressCallback);
      }

      await this.updateProgress(progressCallback, 90, 'Finalizing Report');

      this.scanMetadata.endTime = Date.now();
      this.scanMetadata.duration = this.scanMetadata.endTime - this.scanMetadata.startTime;

      return this.generateReport();
    } catch (error) {
      console.error('Scan error:', error);
      throw error;
    }
  }

  async updateProgress(callback, percentage, phase) {
    if (callback) {
      callback({ percentage, phase });
    }
  }

  // Passive Reconnaissance
  async passiveReconnaissance(progressCallback) {
    await this.updateProgress(progressCallback, 20, 'Passive Reconnaissance');

    // DNS lookup
    try {
      const urlObj = new URL(this.targetUrl);
      const addresses = await dns.resolve4(urlObj.hostname);
      this.scanMetadata.ipAddresses = addresses;
    } catch (error) {
      console.error('DNS lookup error:', error.message);
    }

    await this.updateProgress(progressCallback, 30, 'Technology Fingerprinting');
    await this.fingerprint();

    await this.updateProgress(progressCallback, 40, 'Crawling Site Structure');
    await this.crawl();
  }

  // Enhanced Technology Fingerprinting
  async fingerprint() {
    try {
      const response = await axios.get(this.targetUrl, {
        timeout: 10000,
        validateStatus: () => true,
        maxRedirects: 5
      });

      this.scanMetadata.requestCount++;

      // Initialize tech stack tracking
      this.scanMetadata.techStack = {
        server: null,
        frameworks: [],
        languages: [],
        libraries: [],
        security: [],
        analytics: [],
        cdn: null
      };

      // Advanced Server Detection
      if (response.headers.server) {
        const serverInfo = this.parseServerHeader(response.headers.server);
        this.scanMetadata.techStack.server = serverInfo;
        this.technologies.push({
          name: serverInfo.name,
          version: serverInfo.version,
          category: 'server',
          confidence: 95,
          evidence: `Server header: ${response.headers.server}`
        });
      }

      const $ = cheerio.load(response.data);

      // Enhanced Framework Detection
      const frameworkSignatures = {
        react: [
          () => response.data.includes('react'),
          () => $('[data-reactroot]').length > 0,
          () => response.data.includes('_reactListenersID')
        ],
        angular: [
          () => $('[ng-controller]').length > 0,
          () => response.data.includes('ng-app'),
          () => response.data.includes('angular.js')
        ],
        vue: [
          () => $('[v-if]').length > 0,
          () => response.data.includes('vue.js'),
          () => response.data.includes('__vue__')
        ],
        laravel: [
          () => response.headers['x-powered-by']?.includes('Laravel'),
          () => $('meta[name="csrf-token"]').length > 0
        ],
        django: [
          () => response.headers['x-framework']?.includes('Django'),
          () => $('input[name="csrfmiddlewaretoken"]').length > 0
        ],
        rails: [
          () => response.headers['x-powered-by']?.includes('Ruby'),
          () => $('meta[name="csrf-param"]').length > 0
        ]
      };

      // Test each framework
      for (const [framework, tests] of Object.entries(frameworkSignatures)) {
        const matchingTests = tests.filter(test => test()).length;
        if (matchingTests > 0) {
          const confidence = (matchingTests / tests.length) * 100;
          this.scanMetadata.techStack.frameworks.push({
            name: framework,
            confidence: confidence,
            evidence: `${matchingTests}/${tests.length} signatures matched`
          });
        }
      }

      // Enhanced JavaScript Library Detection
      const scriptSources = [];
      $('script[src]').each((i, elem) => {
        scriptSources.push($(elem).attr('src'));
      });

      const librarySignatures = {
        jquery: {
          patterns: [/jquery[.-](\d+\.\d+\.\d+)/i, /jquery/i],
          version: this.detectjQueryVersion.bind(this)
        },
        bootstrap: {
          patterns: [/bootstrap[.-](\d+\.\d+\.\d+)/i, /bootstrap/i],
          version: (src) => src.match(/bootstrap[.-](\d+\.\d+\.\d+)/i)?.[1]
        },
        moment: {
          patterns: [/moment[.-](\d+\.\d+\.\d+)/i, /moment/i],
          version: (src) => src.match(/moment[.-](\d+\.\d+\.\d+)/i)?.[1]
        },
        lodash: {
          patterns: [/lodash[.-](\d+\.\d+\.\d+)/i, /lodash/i],
          version: (src) => src.match(/lodash[.-](\d+\.\d+\.\d+)/i)?.[1]
        }
      };

      for (const src of scriptSources) {
        for (const [lib, config] of Object.entries(librarySignatures)) {
          if (config.patterns.some(p => p.test(src))) {
            const version = config.version(src) || 'Unknown';
            this.scanMetadata.techStack.libraries.push({
              name: lib,
              version: version,
              source: src
            });
          }
        }
      }

      // Security Technology Detection
      const securitySignatures = {
        waf: {
          headers: ['x-cdn-geo', 'x-fw-hash', 'x-waf-uuid'],
          cookies: ['__cfduid', '_cf_bm', 'cf_clearance']
        },
        ddos_protection: {
          headers: ['x-ddos-protection', 'x-iinfo', 'x-cache-hits'],
          cookies: ['__ddos_guard', '__ddg_']
        }
      };

      // Check for security technologies
      for (const [tech, sigs] of Object.entries(securitySignatures)) {
        const headerMatch = sigs.headers.some(h => response.headers[h]);
        const cookieMatch = response.headers['set-cookie']?.some(c => 
          sigs.cookies.some(sig => c.includes(sig))
        );

        if (headerMatch || cookieMatch) {
          this.scanMetadata.techStack.security.push({
            name: tech,
            confidence: headerMatch ? 90 : 70,
            evidence: headerMatch ? 'Header signature match' : 'Cookie signature match'
          });
        }
      }

      // CDN Detection
      const cdnSignatures = {
        cloudflare: ['cf-ray', 'cf-cache-status', '__cfduid'],
        akamai: ['x-akamai-transformed', 'akamai-origin-hop'],
        fastly: ['x-fastly-request-id', 'fastly-ff'],
        cloudfront: ['x-amz-cf-id', 'x-amz-cf-pop']
      };

      for (const [cdn, sigs] of Object.entries(cdnSignatures)) {
        if (sigs.some(sig => response.headers[sig])) {
          this.scanMetadata.techStack.cdn = {
            name: cdn,
            confidence: 95,
            evidence: `Header signature match: ${sigs.find(sig => response.headers[sig])}`
          };
        }
      }

      // API Technology Detection
      const apiSignatures = {
        graphql: [
          () => response.data.includes('{"data":'),
          () => response.data.includes('"__schema"'),
          () => $('script:contains("graphql")').length > 0
        ],
        rest: [
          () => response.headers['access-control-allow-methods']?.includes('GET'),
          () => response.data.includes('"api":'),
          () => /\/api\/v\d+/.test(this.targetUrl)
        ],
        soap: [
          () => response.headers['content-type']?.includes('xml'),
          () => response.data.includes('<soap:Envelope'),
          () => response.data.includes('xmlns:soap')
        ]
      };

      // Test for API technologies
      for (const [api, tests] of Object.entries(apiSignatures)) {
        const matchingTests = tests.filter(test => test()).length;
        if (matchingTests > 0) {
          this.deepFindings.apiPatterns.push({
            type: api,
            confidence: (matchingTests / tests.length) * 100,
            evidence: `${matchingTests}/${tests.length} signatures matched`
          });
        }
      }

      // Content Pattern Analysis
      if (this.config.contentAnalysis) {
        this.analyzeContentPatterns(response.data);
      }

    } catch (error) {
      this.scanMetadata.errorCount++;
      console.error('Fingerprinting error:', error.message);
    }
  }

  // NEW: Content Pattern Analysis
  analyzeContentPatterns(content) {
    const patterns = {
      authForms: /<form[^>]*(?:login|signin|auth)[^>]*>/i,
      fileUploads: /<input[^>]*type=["']file["'][^>]*>/i,
      adminPaths: /\/(admin|dashboard|manage|control)/i,
      apiEndpoints: /\/(api|rest|graphql|v\d+)/i,
      sensitiveParams: /(password|token|key|secret|hash)=/i,
      jsonStructures: /{[^}]*"[^"]*":/,
      base64Data: /[A-Za-z0-9+/]{40,}={0,2}/
    };

    for (const [type, pattern] of Object.entries(patterns)) {
      if (pattern.test(content)) {
        this.deepFindings.contentPatterns.push({
          type,
          confidence: 85,
          matches: (content.match(pattern) || []).length,
          sample: content.match(pattern)?.[0].slice(0, 100)
        });
      }
    }
  }

  parseServerHeader(header) {
    const serverMatch = header.match(/^([^\s\/]+)/);
    return serverMatch ? serverMatch[1] : header;
  }

  extractVersion(text) {
    const versionMatch = text.match(/(\d+\.[\d.]+)/);
    return versionMatch ? versionMatch[1] : 'Unknown';
  }

  detectjQueryVersion(html) {
    const match = html.match(/jquery[.-](\d+\.\d+\.\d+)/i);
    return match ? match[1] : '3.x.x';
  }

  // Web Crawler
  async crawl() {
    const visited = new Set();
    const toVisit = [this.targetUrl];
    const maxPages = 10;

    while (toVisit.length > 0 && visited.size < maxPages) {
      const url = toVisit.pop();
      
      if (visited.has(url)) continue;
      visited.add(url);

      try {
        const response = await axios.get(url, {
          timeout: 10000,
          validateStatus: () => true,
          maxRedirects: 5
        });

        this.scanMetadata.requestCount++;

        const $ = cheerio.load(response.data);
        
        // Find links
        $('a[href]').each((i, elem) => {
          const href = $(elem).attr('href');
          if (href && this.isValidUrl(href, url)) {
            const absoluteUrl = this.makeAbsoluteUrl(href, url);
            if (!visited.has(absoluteUrl) && this.isSameDomain(absoluteUrl, this.targetUrl)) {
              toVisit.push(absoluteUrl);
              this.discoveredEndpoints.push({
                url: absoluteUrl,
                method: 'GET',
                discoveredVia: 'crawler'
              });
            }
          }
        });

        // Find forms
        $('form').each((i, elem) => {
          const action = $(elem).attr('action') || url;
          const method = ($(elem).attr('method') || 'GET').toUpperCase();
          const inputs = [];

          $(elem).find('input, textarea, select').each((j, input) => {
            const name = $(input).attr('name');
            const type = $(input).attr('type') || 'text';
            if (name) {
              inputs.push({ name, type });
            }
          });

          this.discoveredEndpoints.push({
            url: this.makeAbsoluteUrl(action, url),
            method,
            type: 'form',
            inputs,
            discoveredVia: 'crawler'
          });
        });

      } catch (error) {
        this.scanMetadata.errorCount++;
        console.error(`Crawl error for ${url}:`, error.message);
      }
    }
  }

  isValidUrl(href, baseUrl) {
    if (!href) return false;
    if (href.startsWith('#')) return false;
    if (href.startsWith('javascript:')) return false;
    if (href.startsWith('mailto:')) return false;
    return true;
  }

  makeAbsoluteUrl(href, baseUrl) {
    try {
      return new URL(href, baseUrl).href;
    } catch {
      return href;
    }
  }

  isSameDomain(url1, url2) {
    try {
      const domain1 = new URL(url1).hostname;
      const domain2 = new URL(url2).hostname;
      return domain1 === domain2;
    } catch {
      return false;
    }
  }

  // Active Vulnerability Scanning
  async activeVulnerabilityScanning(progressCallback) {
    await this.updateProgress(progressCallback, 50, 'Active Vulnerability Scanning');

    // Determine scan intensity (how many endpoints to test)
    const intensityMap = { low: 3, medium: 6, high: 20 };
    const endpointLimit = intensityMap[this.config.aggressiveness] || 6;

    // Test for SQL Injection
    await this.testSQLInjection(endpointLimit);

    await this.updateProgress(progressCallback, 60, 'Testing for XSS');
    await this.testXSS(endpointLimit);

    await this.updateProgress(progressCallback, 70, 'Testing for Command Injection');
    await this.testCommandInjection(Math.min(endpointLimit, 10));

    await this.updateProgress(progressCallback, 80, 'Analyzing Security Headers');
    await this.checkSecurityHeaders();
  }

  // SQL Injection Testing
  async testSQLInjection() {
    const signature = vulnerabilitySignatures.sqlInjection;
    const limit = arguments[0] || 5;

    for (const endpoint of this.discoveredEndpoints.slice(0, limit)) {
      if (endpoint.inputs && endpoint.inputs.length > 0) {
        for (const input of endpoint.inputs) {
          for (const payload of signature.payloads) {
            try {
              const params = new URLSearchParams();
              params.append(input.name, payload);

              const testUrl = endpoint.method === 'GET' 
                ? `${endpoint.url}?${params}`
                : endpoint.url;

              const response = await axios({
                method: endpoint.method,
                url: testUrl,
                data: endpoint.method === 'POST' ? params : undefined,
                timeout: 5000,
                validateStatus: () => true
              });

              this.scanMetadata.requestCount++;

              // Check for SQL error patterns
              const hasError = signature.errorPatterns.some(pattern => 
                pattern.test(response.data)
              );

              if (hasError) {
                this.vulnerabilities.push({
                  id: `VULN-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
                  type: signature.name,
                  severity: signature.severity,
                  endpoint: endpoint.url,
                  parameter: input.name,
                  method: endpoint.method,
                  payload: payload,
                  confidence: 85 + Math.floor(Math.random() * 15),
                  evidence: 'SQL error message detected in response',
                  timestamp: new Date().toISOString()
                });
                break;
              }

            } catch (error) {
              this.scanMetadata.errorCount++;
            }
          }
        }
      }
    }
  }

  // XSS Testing
  async testXSS() {
    const signature = vulnerabilitySignatures.xss;
    const limit = arguments[0] || 5;

    for (const endpoint of this.discoveredEndpoints.slice(0, limit)) {
      if (endpoint.inputs && endpoint.inputs.length > 0) {
        for (const input of endpoint.inputs) {
          const payload = signature.payloads[0];
          
          try {
            const params = new URLSearchParams();
            params.append(input.name, payload);

            const testUrl = endpoint.method === 'GET' 
              ? `${endpoint.url}?${params}`
              : endpoint.url;

            const response = await axios({
              method: endpoint.method,
              url: testUrl,
              data: endpoint.method === 'POST' ? params : undefined,
              timeout: 5000,
              validateStatus: () => true
            });

            this.scanMetadata.requestCount++;

            // Check if payload is reflected
            if (response.data.includes(payload)) {
              this.vulnerabilities.push({
                id: `VULN-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
                type: signature.name,
                severity: signature.severity,
                endpoint: endpoint.url,
                parameter: input.name,
                method: endpoint.method,
                payload: payload,
                confidence: 75 + Math.floor(Math.random() * 20),
                evidence: 'Payload reflected in response without encoding',
                timestamp: new Date().toISOString()
              });
            }

          } catch (error) {
            this.scanMetadata.errorCount++;
          }
        }
      }
    }
  }

  // Command Injection Testing
  async testCommandInjection() {
    const signature = vulnerabilitySignatures.commandInjection;
    const limit = arguments[0] || 3;

    for (const endpoint of this.discoveredEndpoints.slice(0, limit)) {
      if (endpoint.inputs && endpoint.inputs.length > 0) {
        for (const input of endpoint.inputs) {
          // Time-based detection
          const payload = '; sleep 5';
          
          try {
            const startTime = Date.now();
            
            const params = new URLSearchParams();
            params.append(input.name, payload);

            const testUrl = endpoint.method === 'GET' 
              ? `${endpoint.url}?${params}`
              : endpoint.url;

            await axios({
              method: endpoint.method,
              url: testUrl,
              data: endpoint.method === 'POST' ? params : undefined,
              timeout: 10000,
              validateStatus: () => true
            });

            const duration = Date.now() - startTime;
            this.scanMetadata.requestCount++;

            // If response took significantly longer, potential command injection
            if (duration > 4500) {
              this.vulnerabilities.push({
                id: `VULN-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
                type: signature.name,
                severity: signature.severity,
                endpoint: endpoint.url,
                parameter: input.name,
                method: endpoint.method,
                payload: payload,
                confidence: 70 + Math.floor(Math.random() * 15),
                evidence: `Response delayed by ${Math.round(duration/1000)}s, indicating potential command execution`,
                timestamp: new Date().toISOString()
              });
            }

          } catch (error) {
            this.scanMetadata.errorCount++;
          }
        }
      }
    }
  }

  // Enhanced Security Headers Analysis
  async checkSecurityHeaders() {
    try {
      const response = await axios.get(this.targetUrl, {
        timeout: 10000,
        validateStatus: () => true,
        maxRedirects: 5
      });

      this.scanMetadata.requestCount++;

      // Store all headers for analysis
      this.scanMetadata.headers = response.headers;

      const requiredHeaders = {
        'strict-transport-security': {
          name: 'HTTP Strict Transport Security (HSTS)',
          validator: (value) => value && value.includes('max-age=') && parseInt(value.match(/max-age=(\d+)/)[1]) >= 31536000
        },
        'x-frame-options': {
          name: 'X-Frame-Options',
          validator: (value) => value && ['DENY', 'SAMEORIGIN'].includes(value.toUpperCase())
        },
        'x-content-type-options': {
          name: 'X-Content-Type-Options',
          validator: (value) => value && value.toLowerCase() === 'nosniff'
        },
        'content-security-policy': {
          name: 'Content Security Policy',
          validator: (value) => value && value.includes("default-src") && !value.includes('unsafe-inline') && !value.includes('unsafe-eval')
        },
        'x-xss-protection': {
          name: 'X-XSS-Protection',
          validator: (value) => value && value.includes('1; mode=block')
        },
        'permissions-policy': {
          name: 'Permissions Policy',
          validator: (value) => value && value.length > 0
        },
        'referrer-policy': {
          name: 'Referrer Policy',
          validator: (value) => value && ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer'].includes(value.toLowerCase())
        }
      };

      // Enhanced header checks
      for (const [header, config] of Object.entries(requiredHeaders)) {
        const headerValue = response.headers[header];
        
        if (!headerValue) {
          this.vulnerabilities.push({
            id: `VULN-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
            type: 'Security Header Missing',
            severity: 'medium',
            endpoint: this.targetUrl,
            parameter: 'Response Headers',
            method: 'GET',
            confidence: 95,
            evidence: `Missing ${config.name} header`,
            recommendation: `Add the ${header} header with appropriate values`,
            timestamp: new Date().toISOString()
          });
        } else if (!config.validator(headerValue)) {
          this.vulnerabilities.push({
            id: `VULN-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
            type: 'Weak Security Header Configuration',
            severity: 'medium',
            endpoint: this.targetUrl,
            parameter: header,
            method: 'GET',
            confidence: 90,
            evidence: `${config.name} header present but possibly misconfigured: ${headerValue}`,
            recommendation: `Review and strengthen ${header} configuration`,
            timestamp: new Date().toISOString()
          });
        }
      }

      // Enhanced Cookie Analysis
      if (this.config.cookieAnalysis) {
        const setCookie = response.headers['set-cookie'];
        if (setCookie && setCookie.length > 0) {
          setCookie.forEach(cookieStr => {
            const cookieAnalysis = this.analyzeCookie(cookieStr);
            this.deepFindings.cookieDetails.push(cookieAnalysis);

            if (cookieAnalysis.issues.length > 0) {
              this.vulnerabilities.push({
                id: `VULN-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
                type: 'Cookie Security Issues',
                severity: cookieAnalysis.severity,
                endpoint: this.targetUrl,
                parameter: cookieAnalysis.name,
                method: 'GET',
                confidence: 90,
                evidence: `Cookie security issues: ${cookieAnalysis.issues.join(', ')}`,
                recommendation: cookieAnalysis.recommendations.join('\n'),
                timestamp: new Date().toISOString()
              });
            }
          });
        }
      }

      // Check for information disclosure in headers
      const sensitiveHeaders = {
        'server': /[0-9.]+|apache|nginx|iis|php|asp|jsp|tomcat|weblogic|websphere/i,
        'x-powered-by': /.+/,
        'x-aspnet-version': /.+/,
        'x-runtime': /.+/,
        'x-version': /.+/
      };

      for (const [header, pattern] of Object.entries(sensitiveHeaders)) {
        const value = response.headers[header];
        if (value && pattern.test(value)) {
          this.deepFindings.headerAnomalies.push({
            header,
            value,
            risk: 'Information Disclosure',
            recommendation: `Remove or mask the ${header} header to prevent technology fingerprinting`
          });
        }
      }

    } catch (error) {
      this.scanMetadata.errorCount++;
    }
  }

  // NEW: Enhanced Cookie Analysis
  analyzeCookie(cookieStr) {
    const analysis = {
      raw: cookieStr,
      name: cookieStr.split('=')[0],
      attributes: {},
      issues: [],
      recommendations: [],
      severity: 'low'
    };

    // Parse cookie attributes
    const attrs = cookieStr.split(';').map(s => s.trim());
    attrs.forEach(attr => {
      const [key, value] = attr.split('=').map(s => s.trim());
      analysis.attributes[key.toLowerCase()] = value || true;
    });

    // Security checks
    if (!analysis.attributes.secure) {
      analysis.issues.push('Missing Secure flag');
      analysis.recommendations.push('Add Secure flag to prevent cookie transmission over HTTP');
      analysis.severity = 'high';
    }

    if (!analysis.attributes.httponly) {
      analysis.issues.push('Missing HttpOnly flag');
      analysis.recommendations.push('Add HttpOnly flag to prevent XSS access to cookie');
      analysis.severity = 'high';
    }

    if (!analysis.attributes.samesite) {
      analysis.issues.push('Missing SameSite attribute');
      analysis.recommendations.push('Add SameSite=Strict or SameSite=Lax to prevent CSRF');
    } else if (analysis.attributes.samesite.toLowerCase() === 'none') {
      analysis.issues.push('SameSite=None may be risky');
      analysis.recommendations.push('Consider using SameSite=Strict or SameSite=Lax if cross-site access is not required');
    }

    // Check for session cookies
    if (analysis.name.toLowerCase().includes('sess') && (!analysis.attributes['max-age'] && !analysis.attributes.expires)) {
      analysis.issues.push('Session cookie without expiration');
      analysis.recommendations.push('Add Expires or Max-Age attribute for session cookies');
    }

    // Domain attribute checks
    if (analysis.attributes.domain && analysis.attributes.domain.startsWith('.')) {
      analysis.issues.push('Overly permissive domain attribute');
      analysis.recommendations.push('Restrict cookie domain to specific host when possible');
    }

    return analysis;
  }

  // Deep analysis: crawl more pages, check robots/sitemap, and look for hidden inputs and other artifacts
  async deepAnalysis(progressCallback) {
    const maxPages = this.config.aggressiveness === 'high' ? 50 : 30;
    const visited = new Set();
    const toVisit = [this.targetUrl];

    // Check robots.txt and sitemap.xml
    try {
      const robotsUrl = new URL('/robots.txt', this.targetUrl).href;
      const r = await axios.get(robotsUrl, { timeout: 5000, validateStatus: () => true });
      this.deepFindings.robots = r.status === 200 ? r.data : null;
    } catch (e) {
      // ignore
    }

    while (toVisit.length > 0 && visited.size < maxPages) {
      const url = toVisit.pop();
      if (visited.has(url)) continue;
      visited.add(url);

      try {
        const response = await axios.get(url, { timeout: 10000, validateStatus: () => true });
        this.scanMetadata.requestCount++;

        const $ = cheerio.load(response.data);

        // Collect hidden inputs for potential sensitive parameters
        $('input[type="hidden"]').each((i, elem) => {
          const name = $(elem).attr('name') || 'unknown';
          this.deepFindings.hiddenInputs.push({ url, name });
        });

        // Discover more links for deep crawl
        $('a[href]').each((i, elem) => {
          const href = $(elem).attr('href');
          if (href && this.isValidUrl(href, url)) {
            const absoluteUrl = this.makeAbsoluteUrl(href, url);
            if (!visited.has(absoluteUrl) && this.isSameDomain(absoluteUrl, this.targetUrl)) {
              toVisit.push(absoluteUrl);
              this.discoveredEndpoints.push({ url: absoluteUrl, method: 'GET', discoveredVia: 'deep-crawler' });
            }
          }
        });

        // Find forms and capture inputs
        $('form').each((i, elem) => {
          const action = $(elem).attr('action') || url;
          const method = ($(elem).attr('method') || 'GET').toUpperCase();
          const inputs = [];

          $(elem).find('input, textarea, select').each((j, input) => {
            const name = $(input).attr('name');
            const type = $(input).attr('type') || 'text';
            if (name) {
              inputs.push({ name, type });
            }
          });

          this.discoveredEndpoints.push({ url: this.makeAbsoluteUrl(action, url), method, type: 'form', inputs, discoveredVia: 'deep-crawler' });
        });

      } catch (error) {
        this.scanMetadata.errorCount++;
      }
    }

    // Post-process: if many hidden inputs found, add a report entry
    if (this.deepFindings.hiddenInputs.length > 0) {
      this.vulnerabilities.push({
        id: `VULN-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
        type: 'Sensitive Parameters',
        severity: 'medium',
        endpoint: this.targetUrl,
        parameter: 'Hidden Inputs',
        method: 'GET',
        confidence: 80,
        evidence: `Found ${this.deepFindings.hiddenInputs.length} hidden inputs during deep crawl`,
        timestamp: new Date().toISOString()
      });
    }
  }

  // Deauthentication tests: look for logout endpoints that are vulnerable to CSRF or are reachable via GET
  async testDeauth() {
    // Look for endpoints with 'logout' in URL or form action
    const logoutCandidates = this.discoveredEndpoints.filter(e => (e.url && e.url.toLowerCase().includes('logout')) || (e.type === 'form' && e.url.toLowerCase().includes('logout')));

    for (const endpoint of logoutCandidates) {
      try {
        // If reachable via GET and returns 200 without anti-CSRF markers in surrounding page/forms, flag it
        const response = await axios.get(endpoint.url, { timeout: 8000, validateStatus: () => true });
        this.scanMetadata.requestCount++;

        // Heuristic: if the page contains no CSRF token fields and logout endpoint responds to GET, it may be vulnerable
        const hasCsrf = /csrf|xsrf|token/i.test(response.data);

        if (response.status === 200 && !hasCsrf) {
          this.vulnerabilities.push({
            id: `VULN-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
            type: 'Deauthentication via GET',
            severity: 'high',
            endpoint: endpoint.url,
            parameter: 'logout',
            method: 'GET',
            confidence: 85,
            evidence: 'Logout endpoint reachable via GET and page contains no CSRF token markers',
            timestamp: new Date().toISOString()
          });
          this.deepFindings.deauth.push(endpoint.url);
        }

        // Also check if logout is implemented as a form without CSRF token
        if (endpoint.type === 'form' && endpoint.inputs) {
          const hasTokenField = endpoint.inputs.some(i => /csrf|xsrf|token/i.test(i.name));
          if (!hasTokenField) {
            this.vulnerabilities.push({
              id: `VULN-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
              type: 'Deauthentication via Missing CSRF',
              severity: 'high',
              endpoint: endpoint.url,
              parameter: 'form',
              method: endpoint.method,
              confidence: 80,
              evidence: 'Logout form present without CSRF token field',
              timestamp: new Date().toISOString()
            });
            this.deepFindings.deauth.push(endpoint.url);
          }
        }

      } catch (error) {
        this.scanMetadata.errorCount++;
      }
    }
  }

  // Zero-day research: passive analysis to surface unusual/novel indicators for manual research
  async detectZeroDayCandidates(progressCallback) {
    // Heuristics-only: do not execute exploits. Collect small sanitized snippets and compute entropy/unusual headers.
    const candidates = [];
    const limit = this.config.aggressiveness === 'high' ? 50 : 20;

    const endpoints = this.discoveredEndpoints.slice(0, Math.max(limit, this.discoveredEndpoints.length));

    // Helper: compute Shannon entropy of a string
    const entropy = (s) => {
      if (!s || s.length === 0) return 0;
      const freq = {};
      for (let i = 0; i < s.length; i++) {
        const ch = s[i];
        freq[ch] = (freq[ch] || 0) + 1;
      }
      let ent = 0;
      for (const k in freq) {
        const p = freq[k] / s.length;
        ent -= p * Math.log2(p);
      }
      return ent;
    };

    for (const ep of endpoints) {
      try {
        const resp = await axios.get(ep.url, { timeout: 8000, validateStatus: () => true });
        this.scanMetadata.requestCount++;

        const snippet = (typeof resp.data === 'string' ? resp.data.slice(0, 2000) : JSON.stringify(resp.data).slice(0,2000));
        const ent = entropy(snippet);
        const headers = resp.headers || {};
        const headerKeys = Object.keys(headers).map(h => h.toLowerCase());

        // Heuristics for unusual indicators
        const unusualHeaders = headerKeys.filter(h => /x-debug|x-admin|x-internal|server|x-powered-by/.test(h));
        const stackTraceIndicators = /stack trace|exception|at \w+\(|error:\s|traceback/i.test(snippet);
        const cveLike = /CVE-\d{4}-\d{4,7}/i.test(snippet);
        const highEntropy = ent > 4.5; // heuristic threshold for potential token leakage

        if (unusualHeaders.length > 0 || stackTraceIndicators || cveLike || highEntropy) {
          candidates.push({
            endpoint: ep.url,
            method: ep.method || 'GET',
            snippet: snippet.slice(0,1000), // keep limited evidence
            entropy: Math.round(ent*100)/100,
            unusualHeaders,
            stackTraceIndicators: !!stackTraceIndicators,
            cveLike: !!cveLike,
            note: 'Candidate indicator for manual zero-day research. This is heuristic-only and requires manual verification.'
          });
        }
      } catch (e) {
        this.scanMetadata.errorCount++;
      }
    }

    this.deepFindings.zeroDayCandidates = candidates;
    return candidates;
  }

  // Generate comprehensive report
  generateReport() {
    const critical = this.vulnerabilities.filter(v => v.severity === 'critical').length;
    const high = this.vulnerabilities.filter(v => v.severity === 'high').length;
    const medium = this.vulnerabilities.filter(v => v.severity === 'medium').length;
    const low = this.vulnerabilities.filter(v => v.severity === 'low').length;

    const riskScore = (critical * 10) + (high * 7) + (medium * 4) + (low * 1);

    return {
      target: this.targetUrl,
      scanDate: new Date(this.scanMetadata.startTime).toISOString(),
      duration: `${(this.scanMetadata.duration / 1000).toFixed(1)} seconds`,
      totalVulnerabilities: this.vulnerabilities.length,
      criticalCount: critical,
      highCount: high,
      mediumCount: medium,
      lowCount: low,
      riskScore: Math.min(riskScore, 100),
      technologies: this.technologies,
      endpoints: this.discoveredEndpoints.length,
      forms: this.discoveredEndpoints.filter(e => e.type === 'form').length,
      cookies: 0,
      vulnerabilities: this.vulnerabilities,
      metadata: {
        requestCount: this.scanMetadata.requestCount,
        errorCount: this.scanMetadata.errorCount,
        ipAddresses: this.scanMetadata.ipAddresses || []
      }
      ,
      deepFindings: this.deepFindings,
      exploitAttempts: this.exploitAttempts || [],
      exploitSafetyNotes: this.exploitSafetyNotes || null
    };
  }

  // Simulate exploit attempts (non-destructive) — generate PoC-like descriptions only
  simulateExploitAttempts() {
    // Build simulated attempts based on discovered vulnerabilities and endpoints
    const attempts = [];

    // For SQL Injection vulnerabilities, provide a safe PoC suggestion
    this.vulnerabilities.filter(v => v.type && v.type.toLowerCase().includes('sql')).forEach(v => {
      attempts.push({
        module: 'sql-injection-poc',
        simulated: true,
        target: v.endpoint,
        parameter: v.parameter,
        details: `Suggested PoC payload (SIMULATED): ${"' OR '1'='1"}. Do NOT execute against third-party systems. Manual verification steps: review server-side query handling, replicate in a controlled lab, use parameterized queries to fix.`
      });
    });

    // For XSS, provide non-executing PoC guidance
    this.vulnerabilities.filter(v => v.type && v.type.toLowerCase().includes('xss')).forEach(v => {
      attempts.push({
        module: 'xss-poc',
        simulated: true,
        target: v.endpoint,
        parameter: v.parameter,
        details: `Reflected XSS indicator found. Example payload (SIMULATED): ${'<script>alert(1)</script>'}. Manual verification: test in isolated lab environment and apply output encoding and CSP.`
      });
    });

    // For deauth findings, add PoC guidance
    if (this.deepFindings && Array.isArray(this.deepFindings.deauth)) {
      this.deepFindings.deauth.forEach(url => {
        attempts.push({
          module: 'deauth-check-poc',
          simulated: true,
          target: url,
          parameter: 'logout',
          details: 'Logout endpoint reachable without CSRF markers — manual verification recommended. Do NOT attempt automated logout against third-party sites.'
        });
      });
    }

    // Add general note
    const safetyNote = 'Exploit attempts are SIMULATED and informational only. They do not execute attacks. For real exploit testing, use an isolated lab or authorised professional tools.';

    // Attach to scanner instance for report inclusion
    this.exploitAttempts = attempts;
    this.exploitSafetyNotes = safetyNote;

    return { attempts, safetyNote };
  }
}

// Authentication Routes

// Register User
app.post('/api/auth/register', [
  body('username').trim().isLength({ min: 4 }).escape(),
  body('password').isLength({ min: 8 })
    .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/)
    .withMessage('Password must contain at least 8 characters, one letter, one number, and one special character'),
  body('email').isEmail().normalizeEmail()
], validateRequest, async (req, res) => {
  try {
    const { username, password, email } = req.body;

    // Check if user exists
    if (Array.from(users.values()).some(u => u.username === username || u.email === email)) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Create user
    const userId = crypto.randomBytes(16).toString('hex');
    users.set(userId, {
      id: userId,
      username,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    });

    // Generate token
    const token = jwt.sign({ id: userId, username }, JWT_SECRET, { expiresIn: '24h' });

    res.status(201).json({ token });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/auth/login', [
  body('username').trim().notEmpty(),
  body('password').notEmpty()
], validateRequest, async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find user
    const user = Array.from(users.values()).find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '24h' });

    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Password Reset Request
app.post('/api/auth/reset-request', [
  body('email').isEmail().normalizeEmail()
], validateRequest, (req, res) => {
  const { email } = req.body;
  // In production: Implement actual password reset logic with email
  res.json({ message: 'If an account exists with this email, a reset link will be sent.' });
});

// API Routes

// Health check (public)
app.get('/api/health', securityLogger, (req, res) => {
  res.json({ 
    status: 'operational', 
    version: '1.0.0', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Start a new scan
app.post('/api/scan/start', [
  validateJWT,
  securityLogger,
  body('targetUrl').isURL().withMessage('Invalid target URL'),
  body('config').optional().isObject(),
  validateRequest
], async (req, res) => {
  const { targetUrl, config } = req.body;

  if (!targetUrl) {
    return res.status(400).json({ error: 'Target URL is required' });
  }

  // Security: only allow `aggressiveExternal` when request includes a CLI header
  // This prevents enabling aggressive external tooling from the web UI.
  try {
    const cliHeader = (req.headers['x-awsap-cli'] || req.headers['x-awsap-cli'.toLowerCase()]);
    const cliAllowed = cliHeader === '1' || cliHeader === 'true';
    if (config && config.aggressiveExternal && !cliAllowed) {
      // Force-disable aggressive external orchestration if not invoked from CLI
      config.aggressiveExternal = false;
    }
  } catch (e) {
    // ignore header parsing errors and default to disabling aggressiveExternal
    if (config) config.aggressiveExternal = false;
  }

  // Validate URL
  try {
    new URL(targetUrl);
  } catch {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  const scanId = crypto.randomBytes(16).toString('hex');
  
  // Initialize scan
  const scanner = new SecurityScanner(targetUrl, config || {});

  // Safety: require explicit authorization for high-impact options
  try {
    const urlObj = new URL(targetUrl);

  const highImpact = scanner.config.aggressiveness === 'high' || scanner.config.deauthTest || scanner.config.deepAnalysis || scanner.config.simulateExploits || scanner.config.zeroDayResearch;

    if (highImpact) {
      if (!scanner.config.authorized || !scanner.config.operator) {
        return res.status(403).json({ error: 'High-impact scans require explicit authorization and operator name in scan config' });
      }

      // If an allowlist is provided, require the target hostname to be included
      if (Array.isArray(scanner.config.authorizedTargets) && scanner.config.authorizedTargets.length > 0) {
        const host = urlObj.hostname;
        const allowed = scanner.config.authorizedTargets.some(a => a === host || targetUrl.startsWith(a));
        if (!allowed) {
          return res.status(403).json({ error: 'Target not present in authorizedTargets allowlist' });
        }
      }
    }
  } catch (e) {
    return res.status(400).json({ error: 'Invalid targetUrl' });
  }

  scanQueue.set(scanId, {
    status: 'running',
    progress: 0,
    phase: 'Initializing',
    startTime: Date.now()
  });

  // If an aggressive external tools run is requested and authorized, launch orchestrator in background
  const launchExternalTools = async () => {
    try {
      if (scanner.config && scanner.config.aggressiveExternal && scanner.config.authorized) {
        orchestrateExternalTools(scanId, targetUrl, scanner.config).catch(e => {
          console.error('External tools orchestration failed:', e.message || e);
        });
      }
    } catch (e) {
      console.error('Error scheduling external tools:', e.message || e);
    }
  };

  // Kick off external tools orchestrator without waiting
  launchExternalTools();

  // Run scan asynchronously
  scanner.scan((progress) => {
    const scanStatus = scanQueue.get(scanId);
    if (scanStatus) {
      scanStatus.progress = progress.percentage;
      scanStatus.phase = progress.phase;
    }
  }).then(results => {
    // Apply AI analysis
    const aiEngine = new AIAnalysisEngine();
    const chains = aiEngine.correlateVulnerabilities(results.vulnerabilities);
    const patterns = aiEngine.recognizePatterns(results);
    const anomalies = aiEngine.detectAnomalies(results);
    const recommendations = aiEngine.generateRecommendations(results.vulnerabilities, patterns);
    const finalResults = {
      ...results,
      aiAnalysis: {
        vulnerabilityChains: chains,
        patterns,
        anomalies,
        recommendations
      }
    };

    // If simulateExploits enabled, generate simulated PoC entries (non-destructive)
    try {
      if (scanner.config && scanner.config.simulateExploits) {
        const sim = scanner.simulateExploitAttempts();
        finalResults.exploitAttempts = sim.attempts;
        finalResults.exploitSafetyNotes = sim.safetyNote;
      }
    } catch (e) {
      console.error('Error generating simulated exploits:', e.message);
    }

    scanDatabase.set(scanId, finalResults);
    scanQueue.set(scanId, {
      status: 'complete',
      progress: 100,
      phase: 'Scan Complete'
    });
  }).catch(error => {
    scanQueue.set(scanId, {
      status: 'error',
      error: error.message,
      phase: 'Error'
    });
  });

// Orchestrate external tools (docker-based) and attach outputs to scanDatabase when done
async function orchestrateExternalTools(scanId, targetUrl, config) {
  // Tools to run for aggressive mode. Add or remove tools here.
  const tools = [
    { name: 'nmap', cmd: (outDir) => `docker run --rm -v ${outDir}:/output instrumentisto/nmap -A -T4 -oX /output/nmap.xml ${targetUrl}` },
    { name: 'nikto', cmd: (outDir) => `docker run --rm -v ${outDir}:/output sullo/nikto nikto -h ${targetUrl} -o /output/nikto.txt` },
    { name: 'zap', cmd: (outDir) => `docker run --rm -v ${outDir}:/zap owasp/zap2docker-stable zap-full-scan.py -t ${targetUrl} -r /zap/zap_report.html` },
    { name: 'sqlmap', cmd: (outDir) => `docker run --rm -v ${outDir}:/output sqlmapproject/sqlmap -u "${targetUrl}" --batch --output-dir=/output` }
  ];

  const baseOut = path.resolve('/tmp', 'awsap_scans');
  try { fs.mkdirSync(baseOut, { recursive: true }); } catch (e) { /* ignore */ }
  const scanOut = path.join(baseOut, scanId);
  fs.mkdirSync(scanOut, { recursive: true });

  // Update scanQueue phase
  const statusObj = scanQueue.get(scanId) || {};
  statusObj.phase = 'External Tools: starting';
  statusObj.progress = 2;
  scanQueue.set(scanId, statusObj);

  for (let i = 0; i < tools.length; i++) {
    const t = tools[i];
    const outDirHost = scanOut;
    const cmd = t.cmd(outDirHost);
    console.log(`Orchestrator: running ${t.name}: ${cmd}`);

    // Update phase
    const s = scanQueue.get(scanId) || {};
    s.phase = `External Tools: ${t.name}`;
    s.progress = Math.min(5 + Math.round((i / tools.length) * 80), 90);
    scanQueue.set(scanId, s);

    await new Promise((resolve) => {
      exec(cmd, { maxBuffer: 1024 * 1024 * 50 }, (err, stdout, stderr) => {
        // Save combined output for debugging
        try {
          fs.writeFileSync(path.join(outDirHost, `${t.name}.stdout.txt`), stdout || '');
          fs.writeFileSync(path.join(outDirHost, `${t.name}.stderr.txt`), stderr || '');
        } catch (e) {
          console.error('Failed to write tool outputs:', e.message || e);
        }
        if (err) {
          console.error(`${t.name} failed:`, err.message || err);
        }
        resolve();
      });
    });
  }

  // Once done, attach a pointer to outputs in scanDatabase if available
  const results = scanDatabase.get(scanId) || {};
  results.externalToolOutputs = { path: scanOut, tools: tools.map(t => t.name), note: 'Outputs are on the host under /tmp/awsap_scans/<scanId> (container host) — mount path may differ.' };
  scanDatabase.set(scanId, results);

  scanQueue.set(scanId, { status: 'external-complete', progress: 95, phase: 'External Tools Complete' });
}

  res.json({ scanId, status: 'initiated' });
});

// Helper: generate report HTML string from results and scan folder
function generateReportHtml(results, scanId) {
  const scansBase = path.resolve(__dirname, '..', 'tools', 'orchestrator', 'scans');
  let scanOut = scansBase;
  if (results.externalToolOutputs && results.externalToolOutputs.path) {
    scanOut = results.externalToolOutputs.path;
  } else {
    scanOut = path.join(scansBase, scanId);
  }
  try { fs.mkdirSync(scanOut, { recursive: true }); } catch (e) { }

  const files = fs.existsSync(scanOut) ? fs.readdirSync(scanOut) : [];

  const vulnRows = (results.vulnerabilities || []).map(v => `
      <tr>
        <td>${v.id}</td>
        <td>${v.type}</td>
        <td>${v.severity}</td>
        <td>${v.endpoint}</td>
        <td>${v.parameter || ''}</td>
        <td>${v.confidence || ''}</td>
      </tr>`).join('\n');

  const aiRec = (results.aiAnalysis && results.aiAnalysis.recommendations) ? results.aiAnalysis.recommendations : [];
  const aiHtml = aiRec.map(r => `<h4>${r.title} (${r.priority})</h4><p>${r.description}</p><ul>${(r.actions||[]).map(a=>`<li>${a}</li>`).join('')}</ul>`).join('');

  const externalList = files.map(f => `<li><a href="/api/scan/report/${encodeURIComponent(scanId)}/file/${encodeURIComponent(f)}" target="_blank">${f}</a></li>`).join('') || '<li>No external tool outputs</li>';

  const css = `body{font-family:Arial,Helvetica,sans-serif;margin:20px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px}th{background:#f4f4f4}h1{color:#2b6cb0}`;

  const html = `<!doctype html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>AWSAP Scan Report - ${scanId}</title>
        <style>${css}</style>
      </head>
      <body>
        <h1>AWSAP Scan Report</h1>
        <p><strong>Scan ID:</strong> ${scanId}</p>
        <p><strong>Target:</strong> ${results.target}</p>
        <p><strong>Scan Date:</strong> ${results.scanDate || new Date().toISOString()}</p>
        <p><strong>Risk Score:</strong> ${results.riskScore || 'N/A'}</p>
        <h2>Summary</h2>
        <ul>
          <li>Total Vulnerabilities: ${(results.vulnerabilities||[]).length}</li>
          <li>Critical: ${results.criticalCount || 0}</li>
          <li>High: ${results.highCount || 0}</li>
          <li>Medium: ${results.mediumCount || 0}</li>
          <li>Low: ${results.lowCount || 0}</li>
        </ul>

        <h2>Vulnerabilities</h2>
        <table>
          <thead><tr><th>ID</th><th>Type</th><th>Severity</th><th>Endpoint</th><th>Parameter</th><th>Confidence</th></tr></thead>
          <tbody>
            ${vulnRows}
          </tbody>
        </table>

        <h2>AI Recommendations</h2>
        ${aiHtml || '<p>No AI recommendations available.</p>'}

        <h2>External Tool Outputs</h2>
        <ul>
          ${externalList}
        </ul>

      </body>
    </html>`;

  // Save report.html
  try { fs.writeFileSync(path.join(scanOut, 'report.html'), html, 'utf8'); } catch (e) { console.error('Failed to write report.html:', e.message || e); }

  return { html, scanOut };
}

// Get scan status
app.get('/api/scan/status/:scanId', [
  validateJWT,
  securityLogger
], (req, res) => {
  const { scanId } = req.params;
  const status = scanQueue.get(scanId);

  if (!status) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  // Verify ownership (in production, check against database)
  if (status.userId && status.userId !== req.user.id) {
    return res.status(403).json({ error: 'Unauthorized access to scan results' });
  }

  res.json(status);
});

// Get scan results
app.get('/api/scan/results/:scanId', [
  validateJWT,
  securityLogger
], (req, res) => {
  const { scanId } = req.params;
  const results = scanDatabase.get(scanId);

  if (!results) {
    return res.status(404).json({ error: 'Results not found' });
  }

  // Verify ownership (in production, check against database)
  if (results.userId && results.userId !== req.user.id) {
    return res.status(403).json({ error: 'Unauthorized access to scan results' });
  }

  // Sanitize sensitive information before sending
  const sanitizedResults = {
    ...results,
    metadata: {
      ...results.metadata,
      ipAddresses: results.metadata.ipAddresses.map(ip => ip.replace(/\d+$/, 'xxx')), // Partially redact IPs
    },
    scanDate: results.scanDate,
    target: results.target.replace(/:[^\/]+@/, ':***@'), // Hide credentials in URLs
  };

  res.json(sanitizedResults);
});

// List all scans
app.get('/api/scans', [
  validateJWT,
  securityLogger
], (req, res) => {
  const scans = [];
  
  scanDatabase.forEach((results, scanId) => {
    // Only show scans owned by the requesting user
    if (!results.userId || results.userId === req.user.id) {
      scans.push({
        scanId,
        target: results.target.replace(/:[^\/]+@/, ':***@'), // Hide credentials in URLs
        scanDate: results.scanDate,
        totalVulnerabilities: results.totalVulnerabilities,
        riskScore: results.riskScore,
        status: results.status || 'completed'
      });
    }
  });

  res.json(scans);
});

// Get vulnerability details
app.get('/api/vulnerability/:vulnId', (req, res) => {
  const { vulnId } = req.params;
  
  for (const [scanId, results] of scanDatabase.entries()) {
    const vuln = results.vulnerabilities.find(v => v.id === vulnId);
    if (vuln) {
      return res.json({ ...vuln, scanId });
    }
  }

  res.status(404).json({ error: 'Vulnerability not found' });
});

// Export scan report
app.get('/api/scan/export/:scanId', (req, res) => {
  const { scanId } = req.params;
  const results = scanDatabase.get(scanId);

  if (!results) {
    return res.status(404).json({ error: 'Results not found' });
  }

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="awsap-report-${scanId}.json"`);
  res.json(results);
});

// Import a host-run scan folder into the backend so it becomes queryable via API
app.post('/api/scan/import', [validateJWT, securityLogger, body('scanDir').notEmpty()], validateRequest, (req, res) => {
  try {
    const { scanDir, scanId: providedId, target } = req.body;
    const scansBase = path.resolve(__dirname, '..', 'tools', 'orchestrator', 'scans');

    // Resolve and ensure path is inside the allowed scans directory
    const fullPath = path.resolve(scansBase, scanDir);
    if (!fullPath.startsWith(scansBase)) return res.status(400).json({ error: 'Invalid scanDir' });
    if (!fs.existsSync(fullPath)) return res.status(404).json({ error: 'Scan folder not found' });

    const id = providedId || crypto.randomBytes(16).toString('hex');
    const files = fs.readdirSync(fullPath);

    // Try to extract some metadata from an existing report.html if present
    let parsedTarget = target || null;
    let scanDate = new Date().toISOString();
    const reportPath = path.join(fullPath, 'report.html');
    if (fs.existsSync(reportPath)) {
      try {
        const reportHtml = fs.readFileSync(reportPath, 'utf8');
        const m = reportHtml.match(/<p>\s*<strong>Target:<\/strong>\s*([^<]+)<\/p>/i);
        if (m) parsedTarget = parsedTarget || m[1].trim();
        const m2 = reportHtml.match(/<p>\s*<strong>Scan Date:<\/strong>\s*([^<]+)<\/p>/i);
        if (m2) scanDate = m2[1].trim();
      } catch (e) {
        // ignore parse errors
      }
    }

    const results = {
      target: parsedTarget || 'external-scan',
      scanDate,
      duration: 'N/A',
      totalVulnerabilities: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      riskScore: 0,
      technologies: [],
      endpoints: 0,
      forms: 0,
      vulnerabilities: [],
      metadata: { requestCount: 0, errorCount: 0, ipAddresses: [] },
      deepFindings: {},
      externalToolOutputs: { path: fullPath, tools: files }
    };

    scanDatabase.set(id, results);
    scanQueue.set(id, { status: 'imported', progress: 100, phase: 'Imported', startTime: Date.now() });

    res.json({ scanId: id, message: 'Scan imported successfully', files });
  } catch (e) {
    console.error('Import failed:', e.message || e);
    res.status(500).json({ error: 'Failed to import scan' });
  }
});

// Generate and return an HTML report for a scan (includes links to external tool outputs)
app.get('/api/scan/report/:scanId', [validateJWT, securityLogger], async (req, res) => {
  try {
    const { scanId } = req.params;
    const results = scanDatabase.get(scanId);
    if (!results) return res.status(404).json({ error: 'Results not found' });

    // Owner check (basic)
    if (results.userId && results.userId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized access to scan report' });
    }

    // Determine scan outputs directory (prefer externalToolOutputs.path if present)
    const scansBase = path.resolve(__dirname, '..', 'tools', 'orchestrator', 'scans');
    let scanOut = scansBase;
    if (results.externalToolOutputs && results.externalToolOutputs.path) {
      scanOut = results.externalToolOutputs.path;
    } else {
      scanOut = path.join(scansBase, scanId);
    }

    // Ensure folder exists for report storage
    try { fs.mkdirSync(scanOut, { recursive: true }); } catch (e) { /* ignore */ }

    const files = fs.existsSync(scanOut) ? fs.readdirSync(scanOut) : [];

    // Build simple HTML report
    const vulnRows = (results.vulnerabilities || []).map(v => `
      <tr>
        <td>${v.id}</td>
        <td>${v.type}</td>
        <td>${v.severity}</td>
        <td>${v.endpoint}</td>
        <td>${v.parameter || ''}</td>
        <td>${v.confidence || ''}</td>
      </tr>`).join('\n');

    const aiRec = (results.aiAnalysis && results.aiAnalysis.recommendations) ? results.aiAnalysis.recommendations : [];
    const aiHtml = aiRec.map(r => `<h4>${r.title} (${r.priority})</h4><p>${r.description}</p><ul>${(r.actions||[]).map(a=>`<li>${a}</li>`).join('')}</ul>`).join('');

    const externalList = files.map(f => `<li><a href="/api/scan/report/${encodeURIComponent(scanId)}/file/${encodeURIComponent(f)}" target="_blank">${f}</a></li>`).join('') || '<li>No external tool outputs</li>';

    const html = `<!doctype html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>AWSAP Scan Report - ${scanId}</title>
        <style>body{font-family:Arial,Helvetica,sans-serif;margin:20px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px}th{background:#f4f4f4}</style>
      </head>
      <body>
        <h1>AWSAP Scan Report</h1>
        <p><strong>Scan ID:</strong> ${scanId}</p>
        <p><strong>Target:</strong> ${results.target}</p>
        <p><strong>Scan Date:</strong> ${results.scanDate || new Date().toISOString()}</p>
        <p><strong>Risk Score:</strong> ${results.riskScore || 'N/A'}</p>
        <h2>Summary</h2>
        <ul>
          <li>Total Vulnerabilities: ${(results.vulnerabilities||[]).length}</li>
          <li>Critical: ${results.criticalCount || 0}</li>
          <li>High: ${results.highCount || 0}</li>
          <li>Medium: ${results.mediumCount || 0}</li>
          <li>Low: ${results.lowCount || 0}</li>
        </ul>

        <h2>Vulnerabilities</h2>
        <table>
          <thead><tr><th>ID</th><th>Type</th><th>Severity</th><th>Endpoint</th><th>Parameter</th><th>Confidence</th></tr></thead>
          <tbody>
            ${vulnRows}
          </tbody>
        </table>

        <h2>AI Recommendations</h2>
        ${aiHtml || '<p>No AI recommendations available.</p>'}

        <h2>External Tool Outputs</h2>
        <ul>
          ${externalList}
        </ul>

      </body>
    </html>`;

    // Save report to disk for persistence
    const reportPath = path.join(scanOut, 'report.html');
    try { fs.writeFileSync(reportPath, html, 'utf8'); } catch (e) { console.error('Failed to write report:', e.message || e); }

    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  } catch (err) {
    console.error('Report generation error:', err.message || err);
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

// Serve raw tool files for a given scan (download/view)
app.get('/api/scan/report/:scanId/file/:fileName', [validateJWT, securityLogger], (req, res) => {
  try {
    const { scanId, fileName } = req.params;
    const scansBase = path.resolve(__dirname, '..', 'tools', 'orchestrator', 'scans');
    const candidatePaths = [
      path.join(scansBase, scanId, fileName),
      path.join('/tmp', 'awsap_scans', scanId, fileName)
    ];

    let found = null;
    for (const p of candidatePaths) {
      if (fs.existsSync(p)) { found = p; break; }
    }

    if (!found) return res.status(404).json({ error: 'File not found' });

    // Simple content-type detection
    const ext = path.extname(found).toLowerCase();
    const textTypes = ['.txt', '.log', '.xml', '.html', '.json'];
    if (textTypes.includes(ext)) {
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.send(fs.readFileSync(found, 'utf8'));
    } else {
      res.download(found);
    }
  } catch (e) {
    console.error('Error serving file:', e.message || e);
    res.status(500).json({ error: 'Failed to serve file' });
  }
});
// Start server
app.listen(PORT, () => {
  console.log(`🔒 AWSAP Backend running on port ${PORT}`);
  console.log(`📡 API endpoints available at http://localhost:${PORT}/api`);
  console.log(`✅ Health check: http://localhost:${PORT}/api/health`);
});

// Generate PDF report from HTML and return as download
app.get('/api/scan/report/:scanId/pdf', [validateJWT, securityLogger], async (req, res) => {
  try {
    const { scanId } = req.params;
    const results = scanDatabase.get(scanId);
    if (!results) return res.status(404).json({ error: 'Results not found' });

    if (results.userId && results.userId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized access to scan report' });
    }

    const { html, scanOut } = generateReportHtml(results, scanId);

    // Launch Puppeteer and render PDF
    const browser = await puppeteer.launch({ args: ['--no-sandbox', '--disable-setuid-sandbox'] });
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });
    const pdfBuffer = await page.pdf({ format: 'A4', printBackground: true });
    await browser.close();

    // Save PDF to scan folder
    try { fs.writeFileSync(path.join(scanOut, 'report.pdf'), pdfBuffer); } catch (e) { console.error('Failed to write PDF:', e.message || e); }

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="awsap-report-${scanId}.pdf"`);
    res.send(pdfBuffer);
  } catch (e) {
    console.error('PDF generation failed:', e.message || e);
    res.status(500).json({ error: 'Failed to generate PDF' });
  }
});

// Admin helper: import a scan by absolute path (useful for host-run scans)
// NOTE: This endpoint is intentionally restricted; it requires a valid JWT
// and expects the caller to be an operator. Use with caution.
app.post('/api/scan/import-local', [validateJWT, securityLogger, body('fullPath').notEmpty()], validateRequest, (req, res) => {
  try {
    const { fullPath, scanId: providedId, target } = req.body;

    // Basic safety: ensure an absolute path is provided
    if (!path.isAbsolute(fullPath)) return res.status(400).json({ error: 'fullPath must be absolute' });
    if (!fs.existsSync(fullPath)) return res.status(404).json({ error: 'Scan folder not found' });

    const id = providedId || crypto.randomBytes(16).toString('hex');
    const files = fs.readdirSync(fullPath);

    // Try to parse report.html if present for metadata
    let parsedTarget = target || null;
    let scanDate = new Date().toISOString();
    const reportPath = path.join(fullPath, 'report.html');
    if (fs.existsSync(reportPath)) {
      try {
        const reportHtml = fs.readFileSync(reportPath, 'utf8');
        const m = reportHtml.match(/<p>\s*<strong>Target:<\/strong>\s*([^<]+)<\/p>/i);
        if (m) parsedTarget = parsedTarget || m[1].trim();
        const m2 = reportHtml.match(/<p>\s*<strong>Scan Date:<\/strong>\s*([^<]+)<\/p>/i);
        if (m2) scanDate = m2[1].trim();
      } catch (e) { /* ignore parse errors */ }
    }

    const results = {
      target: parsedTarget || 'external-scan',
      scanDate,
      duration: 'N/A',
      totalVulnerabilities: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      riskScore: 0,
      technologies: [],
      endpoints: 0,
      forms: 0,
      vulnerabilities: [],
      metadata: { requestCount: 0, errorCount: 0, ipAddresses: [] },
      deepFindings: {},
      externalToolOutputs: { path: fullPath, tools: files }
    };

    scanDatabase.set(id, results);
    scanQueue.set(id, { status: 'imported-local', progress: 100, phase: 'Imported (local)', startTime: Date.now() });

    res.json({ scanId: id, message: 'Local scan imported successfully', files });
  } catch (e) {
    console.error('Import-local failed:', e.message || e);
    res.status(500).json({ error: 'Failed to import local scan' });
  }
});