// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const sgMail = require('@sendgrid/mail');
const OpenAI = require('openai');
const mammoth = require('mammoth');
const { Client } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { doubleCsrf } = require('csrf-csrf');
const app = express();

// CORS configuration - allow credentials for cookie-based auth
app.use(cors({
    origin: true, // Will be restricted in production
    credentials: true
}));
app.use(cookieParser());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('.'));

const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
const DATABASE_URL = process.env.DATABASE_URL;
const DEFAULT_ADMIN_PASSWORD = process.env.DEFAULT_ADMIN_PASSWORD || 'hradmin@2025';
const SENDGRID_FROM_EMAIL = process.env.SENDGRID_FROM_EMAIL || 'mail@quantzinnovations.com';

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRATION = '30m'; // 30 minutes

// Generate new JWT secret on first run if not in env
if (!process.env.JWT_SECRET) {
    console.warn('⚠️  WARNING: No JWT_SECRET found in environment variables.');
    console.warn('⚠️  Using auto-generated secret. Add this to your .env file:');
    console.warn(`⚠️  JWT_SECRET=${JWT_SECRET}`);
}

// CSRF Protection Configuration
const CSRF_SECRET = process.env.CSRF_SECRET || crypto.randomBytes(32).toString('hex');

if (!process.env.CSRF_SECRET) {
    console.warn('⚠️  WARNING: No CSRF_SECRET found in environment variables.');
    console.warn('⚠️  Using auto-generated secret. Add this to your .env file:');
    console.warn(`⚠️  CSRF_SECRET=${CSRF_SECRET}`);
}

const {
    generateCsrfToken,
    doubleCsrfProtection
} = doubleCsrf({
    getSecret: () => CSRF_SECRET,
    getSessionIdentifier: (req) => req.session?.id || '',  // Session identifier for CSRF
    cookieName: '__Host-psifi.x-csrf-token',
    cookieOptions: {
        sameSite: 'strict',
        path: '/',
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true
    },
    size: 64,
    ignoredMethods: ['GET', 'HEAD', 'OPTIONS']
});

// Initialize OpenRouter client
const openai = new OpenAI({
  baseURL: 'https://openrouter.ai/api/v1',
  apiKey: OPENROUTER_API_KEY,
  defaultHeaders: {
    'HTTP-Referer': 'https://replit.com',
    'X-Title': 'Resume Analyzer AI',
  },
});

sgMail.setApiKey(SENDGRID_API_KEY);

// Database helper functions
async function getDbClient() {
    const client = new Client({
        connectionString: DATABASE_URL,
        // For local Docker Compose, SSL is often not needed/supported by default PostgreSQL image
        // ssl: {
        //     rejectUnauthorized: false
        // }
    });
    await client.connect();
    return client;
}

// JWT Helper Functions
function generateToken(user) {
    return jwt.sign(
        {
            userId: user.id,
            username: user.username,
            isAdmin: user.is_admin
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRATION }
    );
}

// Authentication Middleware - Verify JWT token
function authenticate(req, res, next) {
    const token = req.cookies.jwt;

    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// Authorization Middleware - Verify admin role
function requireAdmin(req, res, next) {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

// Rate limiter for login endpoint
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: 'Too many login attempts, please try again after 15 minutes',
    standardHeaders: true,
    legacyHeaders: false,
});

async function initializeDatabase() {
    const client = await getDbClient();
    try {
        console.log('🔄 Creating users table if not exists...');
        // Create users table if it doesn't exist
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by VARCHAR(50),
                last_login TIMESTAMP
            )
        `);
        console.log('✅ Users table ready');

        // Check if default admin exists
        console.log('🔍 Checking for default admin user...');
        const adminCheck = await client.query('SELECT * FROM users WHERE username = $1', ['hradmin']);

        if (adminCheck.rows.length === 0) {
            console.log('🔄 Creating default admin user...');
            // Create default admin user
            const hashedPassword = await bcrypt.hash(DEFAULT_ADMIN_PASSWORD, 10);
            await client.query(
                'INSERT INTO users (username, password_hash, is_admin, created_by) VALUES ($1, $2, $3, $4)',
                ['hradmin', hashedPassword, true, 'system']
            );
            console.log('✅ Default admin user created successfully');
        } else {
            console.log('✅ Default admin user already exists');
        }

        // Show current user count
        const userCount = await client.query('SELECT COUNT(*) as count FROM users');
        console.log(`📊 Total users in database: ${userCount.rows[0].count}`);

    } catch (error) {
        console.error('❌ Database initialization error:', error);
        console.error('Error details:', error.message);
    } finally {
        await client.end();
    }
}

// User Authentication with JWT
app.post('/api/login', loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const client = await getDbClient();
        try {
            // Always perform bcrypt comparison even for non-existent users (timing attack prevention)
            const dummyHash = '$2b$10$dummyhashfornonexistentusersXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';

            const result = await client.query('SELECT * FROM users WHERE username = $1', [username]);

            const user = result.rows[0];
            const hashToCompare = user ? user.password_hash : dummyHash;

            // Always takes same time to prevent timing attacks
            const isValidPassword = await bcrypt.compare(password, hashToCompare);

            if (!user || !isValidPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            // Update last login
            await client.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

            // Generate JWT token
            const token = generateToken(user);

            // Set HTTP-only cookie with JWT
            res.cookie('jwt', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production', // HTTPS only in production
                sameSite: 'strict',
                maxAge: 30 * 60 * 1000 // 30 minutes
            });

            res.json({
                success: true,
                user: {
                    id: user.id,
                    username: user.username,
                    isAdmin: user.is_admin
                }
            });
        } finally {
            await client.end();
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// CSRF token endpoint - Returns token for frontend to use
app.get('/api/csrf-token', (req, res) => {
    const csrfToken = generateCsrfToken(req, res);
    res.json({ csrfToken });
});

// Logout endpoint
app.post('/api/logout', doubleCsrfProtection, (req, res) => {
    res.clearCookie('jwt');
    res.json({ success: true, message: 'Logged out successfully' });
});

// Get all users (admin only) - NOW WITH PROPER AUTH
app.get('/api/users', authenticate, requireAdmin, async (req, res) => {
    try {
        const client = await getDbClient();
        try {
            const result = await client.query(
                'SELECT id, username, is_admin, created_at, created_by, last_login FROM users ORDER BY created_at DESC'
            );

            res.json(result.rows);
        } finally {
            await client.end();
        }
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Failed to get users' });
    }
});

// Create new user (admin only) - NOW WITH PROPER AUTH + CSRF
app.post('/api/users', doubleCsrfProtection, authenticate, requireAdmin, async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        // Password complexity validation
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({
                error: 'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character'
            });
        }

        const client = await getDbClient();
        try {
            // Check if user limit reached (max 5 non-admin users)
            const userCount = await client.query('SELECT COUNT(*) FROM users WHERE is_admin = FALSE');
            if (parseInt(userCount.rows[0].count) >= 5) {
                return res.status(400).json({ error: 'Maximum 5 users allowed' });
            }

            // Check if username already exists
            const existingUser = await client.query('SELECT * FROM users WHERE username = $1', [username]);
            if (existingUser.rows.length > 0) {
                return res.status(400).json({ error: 'Username already exists' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            const result = await client.query(
                'INSERT INTO users (username, password_hash, is_admin, created_by) VALUES ($1, $2, $3, $4) RETURNING id, username, created_at',
                [username, hashedPassword, false, req.user.username]
            );

            res.json({ success: true, user: result.rows[0] });
        } finally {
            await client.end();
        }
    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({ error: 'Failed to create user' });
    }
});

// Update user password (admin only) - NOW WITH PROPER AUTH + CSRF
app.put('/api/users/:id/password', doubleCsrfProtection, authenticate, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { newPassword } = req.body;

        // Validate user ID
        const userId = parseInt(id);
        if (isNaN(userId) || userId < 1) {
            return res.status(400).json({ error: 'Invalid user ID' });
        }

        // Password complexity validation
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(newPassword)) {
            return res.status(400).json({
                error: 'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character'
            });
        }

        const client = await getDbClient();
        try {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            await client.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedPassword, userId]);
            res.json({ success: true });
        } finally {
            await client.end();
        }
    } catch (error) {
        console.error('Update password error:', error);
        res.status(500).json({ error: 'Failed to update password' });
    }
});

// Delete user (admin only) - NOW WITH PROPER AUTH + CSRF
app.delete('/api/users/:id', doubleCsrfProtection, authenticate, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        // Validate user ID
        const userId = parseInt(id);
        if (isNaN(userId) || userId < 1) {
            return res.status(400).json({ error: 'Invalid user ID' });
        }

        const client = await getDbClient();
        try {
            // Don't allow deleting admin user
            const user = await client.query('SELECT * FROM users WHERE id = $1', [userId]);
            if (user.rows.length > 0 && user.rows[0].is_admin) {
                return res.status(400).json({ error: 'Cannot delete admin user' });
            }

            await client.query('DELETE FROM users WHERE id = $1', [userId]);
            res.json({ success: true });
        } finally {
            await client.end();
        }
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// Request validation and rate limiting
const activeRequests = new Map();
const MAX_CONCURRENT_REQUESTS = 3;
const API_TIMEOUT = 60000; // 60 seconds for complex analysis
const REQUEST_DELAY_TRACKER = new Map(); // Track request timing per IP
const MIN_REQUEST_INTERVAL = 1000; // Minimum 1 second between requests per IP

// Middleware to handle OpenRouter API key for analysis endpoints
const requireApiKey = (req, res, next) => {
    // Use API key from environment variable
    const apiKey = OPENROUTER_API_KEY;

    if (!apiKey || !apiKey.trim()) {
        return res.status(400).json({
            error: 'OpenRouter API key is missing',
            details: 'This product will not run without an OpenRouter API key. Please add OPENROUTER_API_KEY to your Replit Secrets.'
        });
    }

    // Basic API key format validation for OpenRouter
    const trimmedKey = apiKey.trim();
    if (!trimmedKey.startsWith('sk-or-') || trimmedKey.length < 20) {
        return res.status(400).json({
            error: 'Invalid OpenRouter API key format',
            details: 'OpenRouter API keys should start with "sk-or-" and be at least 20 characters long.'
        });
    }

    // Rate limiting check
    const clientId = req.ip || 'unknown';
    const currentRequests = activeRequests.get(clientId) || 0;

    if (currentRequests >= MAX_CONCURRENT_REQUESTS) {
        return res.status(429).json({
            error: 'Too many concurrent requests',
            details: `Maximum ${MAX_CONCURRENT_REQUESTS} concurrent requests allowed per client.`
        });
    }

    // Check minimum interval between requests
    const lastRequestTime = REQUEST_DELAY_TRACKER.get(clientId) || 0;
    const currentTime = Date.now();
    const timeSinceLastRequest = currentTime - lastRequestTime;

    if (timeSinceLastRequest < MIN_REQUEST_INTERVAL) {
        const waitTime = MIN_REQUEST_INTERVAL - timeSinceLastRequest;
        return res.status(429).json({
            error: 'Requests too frequent',
            details: `Please wait ${waitTime}ms before making another request.`,
            retryAfter: Math.ceil(waitTime / 1000)
        });
    }

    // Update request tracking
    REQUEST_DELAY_TRACKER.set(clientId, currentTime);
    activeRequests.set(clientId, currentRequests + 1);

    // Cleanup on response end
    res.on('finish', () => {
        const current = activeRequests.get(clientId) || 0;
        if (current <= 1) {
            activeRequests.delete(clientId);
        } else {
            activeRequests.set(clientId, current - 1);
        }
    });

    req.activeApiKey = trimmedKey;
    next();
};

// Function to query available OpenRouter models
async function queryAvailableModels() {
    try {
        const response = await fetch('https://openrouter.ai/api/v1/models', {
            headers: {
                'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
            }
        });

        if (!response.ok) {
            throw new Error(`Failed to fetch models: ${response.status}`);
        }

        const data = await response.json();
        console.log('Available OpenRouter models:', data.data?.slice(0, 10).map(m => m.id) || []);
        return data.data || [];
    } catch (error) {
        console.error('Error querying models:', error);
        return [];
    }
}

// Robust OpenRouter API call helper
async function makeOpenRouterRequest(prompt, temperature = 0.1) {
    try {
        const completion = await openai.chat.completions.create({
            model: 'openai/gpt-4o-mini',
            messages: [
                {
                    role: 'system',
                    content: 'You are an expert HR analyst specializing in precise resume evaluation. Always return valid JSON arrays with accurate scoring based on exact requirement matches.'
                },
                {
                    role: 'user',
                    content: prompt,
                }
            ],
            temperature: temperature,
            max_tokens: 6000,
            top_p: 0.9,
            frequency_penalty: 0.1,
            presence_penalty: 0.1
        });

        if (!completion.choices || !completion.choices[0] || !completion.choices[0].message) {
            throw new Error('Invalid OpenRouter API response structure');
        }

        return completion.choices[0].message.content.trim();

    } catch (error) {
        if (error.message.includes('timeout')) {
            throw new Error('OpenRouter API request timed out');
        }

        throw new Error(`OpenRouter API error: ${error.message}`);
    }
}

// Robust JSON parsing helper
function parseJSONFromResponse(content, expectedType = 'object') {
    if (!content || typeof content !== 'string') {
        throw new Error('Invalid content for JSON parsing');
    }

    // Clean the content
    let cleanContent = content.trim();

    // Remove common markdown formatting
    cleanContent = cleanContent.replace(/```json\s*/g, '').replace(/```\s*/g, '');

    // Try direct parsing first
    try {
        const parsed = JSON.parse(cleanContent);

        // Validate expected type
        if (expectedType === 'array' && !Array.isArray(parsed)) {
            throw new Error('Expected array but got object');
        }
        if (expectedType === 'object' && (Array.isArray(parsed) || typeof parsed !== 'object')) {
            throw new Error('Expected object but got different type');
        }

        return parsed;
    } catch (parseError) {
        console.log('Direct parsing failed, attempting extraction...');

        // Try to extract JSON from response
        let jsonMatch;
        if (expectedType === 'array') {
            jsonMatch = cleanContent.match(/\[[\s\S]*\]/);
        } else {
            jsonMatch = cleanContent.match(/\{[\s\S]*\}/);
        }

        if (jsonMatch) {
            try {
                const parsed = JSON.parse(jsonMatch[0]);

                // Validate extracted result
                if (expectedType === 'array' && !Array.isArray(parsed)) {
                    throw new Error('Extracted content is not an array');
                }
                if (expectedType === 'object' && (Array.isArray(parsed) || typeof parsed !== 'object')) {
                    throw new Error('Extracted content is not an object');
                }

                return parsed;
            } catch (extractError) {
                console.error('JSON extraction also failed:', extractError);
            }
        }

        // Final fallback - log the problematic content
        console.error('Failed to parse JSON from OpenRouter response:');
        console.error('Original content:', content);
        console.error('Cleaned content:', cleanContent);

        throw new Error(`Could not parse valid JSON from OpenRouter response. Expected ${expectedType} but parsing failed.`);
    }
}

// Extract key requirements from job description using GPT-4o-mini
app.post('/api/extract-job-requirements', requireApiKey, async (req, res) => {
    try {
        const { jobDescription, additionalCriteria = '' } = req.body;

        // Input validation
        if (!jobDescription || typeof jobDescription !== 'string' || jobDescription.trim().length < 50) {
            return res.status(400).json({
                error: 'Invalid job description',
                details: 'Job description must be at least 50 characters long.'
            });
        }

        const trimmedJobDesc = jobDescription.trim();
        if (trimmedJobDesc.length > 50000) {
            return res.status(400).json({
                error: 'Job description too long',
                details: 'Job description must be under 50,000 characters.'
            });
        }

        console.log('Extracting job requirements...');

        const prompt = `Extract and list the key requirements from this job description and additional criteria. Return ONLY a valid JSON object with no additional text, explanations, or formatting.

Job Description:
${trimmedJobDesc}

${additionalCriteria ? `Additional HR Criteria:
${additionalCriteria}` : ''}

Return JSON in this EXACT format (arrays can be empty but must exist):
{
  "technical_skills": ["skill1", "skill2"],
  "experience_requirements": ["requirement1", "requirement2"],
  "education_requirements": ["requirement1", "requirement2"],
  "soft_skills": ["skill1", "skill2"],
  "industry_experience": ["requirement1", "requirement2"],
  "certifications": ["cert1", "cert2"],
  "additional_requirements": ["requirement1", "requirement2"]
}`;

        const fullPrompt = `You are an expert HR analyst. Extract key requirements from job descriptions and return ONLY valid JSON with no additional text, explanations, or markdown formatting.

${prompt}`;

        const content = await makeOpenRouterRequest(fullPrompt, 0.1);

        console.log('Raw content from Gemini:', content);

        const requirements = parseJSONFromResponse(content, 'object');

        // Validate required fields
        const requiredFields = ['technical_skills', 'experience_requirements', 'education_requirements', 'soft_skills', 'industry_experience', 'certifications', 'additional_requirements'];
        for (const field of requiredFields) {
            if (!Array.isArray(requirements[field])) {
                requirements[field] = [];
            }
        }

        console.log('Parsed requirements:', requirements);
        res.json(requirements);

    } catch (error) {
        console.error('Job requirements extraction failed:', error);
        res.status(500).json({
            error: 'Job requirements extraction failed',
            details: error.message
        });
    }
});

// Extract text from Word documents
app.post('/api/extract-word-text', async (req, res) => {
    try {
        const { fileData, fileName } = req.body;

        if (!fileData || !fileName) {
            return res.status(400).json({
                error: 'Missing required fields',
                details: 'fileData and fileName are required'
            });
        }

        // Validate file extension - only allow DOCX
        const fileExtension = fileName.toLowerCase().split('.').pop();
        if (fileExtension !== 'docx') {
            return res.status(400).json({
                error: 'Unsupported file format',
                details: `Only DOCX files are supported. You uploaded a .${fileExtension} file. Please convert to DOCX format and try again.`
            });
        }

        // Enhanced base64 validation
        const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
        if (!fileData || !base64Regex.test(fileData)) {
            console.error(`Invalid base64 data for ${fileName}. Length: ${fileData ? fileData.length : 0}`);
            return res.status(400).json({
                error: 'Invalid file data',
                details: 'File data must be valid base64 encoded'
            });
        }

        console.log(`Processing Word document: ${fileName} (${fileExtension})`);
        console.log(`Base64 data length: ${fileData.length} characters`);

        // Convert base64 to buffer with enhanced error handling
        let buffer;
        try {
            buffer = Buffer.from(fileData, 'base64');
            console.log(`Buffer created successfully. Size: ${buffer.length} bytes`);
        } catch (bufferError) {
            console.error(`Buffer creation failed for ${fileName}:`, bufferError);
            return res.status(400).json({
                error: 'File conversion failed',
                details: `Failed to convert base64 data to buffer: ${bufferError.message}`
            });
        }

        // Validate buffer size (10MB limit)
        const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
        if (buffer.length > MAX_FILE_SIZE) {
            return res.status(400).json({
                error: 'File too large',
                details: 'Word document must be under 10MB'
            });
        }

        // Check if buffer is empty or too small
        if (buffer.length < 100) {
            console.error(`Buffer too small for ${fileName}: ${buffer.length} bytes`);
            return res.status(400).json({
                error: 'Invalid document',
                details: 'Document file appears to be empty or corrupted'
            });
        }

        // Log buffer analysis for debugging
        console.log(`Buffer analysis for ${fileName}:`);
        console.log(`  - Size: ${buffer.length} bytes`);
        console.log(`  - First 20 bytes (hex): ${buffer.slice(0, 20).toString('hex')}`);
        console.log(`  - First 4 bytes (string): ${buffer.slice(0, 4).toString()}`);

        // Check for DOC file signature (older format)
        const docSignature = buffer.slice(0, 8);
        const isLegacyDoc = docSignature.toString('hex').toLowerCase().startsWith('d0cf11e0a1b11ae1');

        // Check for DOCX file signature (newer format)
        const isDocx = buffer.slice(0, 4).toString() === 'PK\x03\x04' || buffer.slice(0, 2).toString() === 'PK';

        console.log(`File type analysis for ${fileName}:`);
        console.log(`  - Extension: ${fileExtension}`);
        console.log(`  - Legacy DOC signature: ${isLegacyDoc}`);
        console.log(`  - DOCX signature: ${isDocx}`);

        // Extract text using mammoth with enhanced error handling and timeout
        let result;
        try {
            console.log(`Starting mammoth extraction for ${fileName}...`);

            // Configure mammoth options for better compatibility
            const mammothOptions = {
                buffer: buffer,
                // Add options for better handling of older formats
                convertImage: mammoth.images.imgElement(function(image) {
                    return image.read("base64").then(function(imageBuffer) {
                        return {
                            src: "data:" + image.contentType + ";base64," + imageBuffer
                        };
                    });
                }),
                // Handle style mappings for better text extraction
                styleMap: [
                    "p[style-name='Normal'] => p:fresh",
                    "p[style-name='Heading 1'] => h1:fresh",
                    "p[style-name='Heading 2'] => h2:fresh"
                ]
            };

            // Add timeout wrapper for mammoth operation
            const mammothPromise = mammoth.extractRawText(mammothOptions);
            const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Mammoth extraction timed out after 45 seconds')), 45000)
            );

            result = await Promise.race([mammothPromise, timeoutPromise]);
            console.log(`Mammoth extraction completed for ${fileName}`);

            // Validate result structure
            if (!result || typeof result !== 'object') {
                throw new Error('Invalid result structure from mammoth');
            }

            if (!result.hasOwnProperty('value')) {
                throw new Error('Missing value property in mammoth result');
            }

        } catch (mammothError) {
            console.error(`Mammoth extraction error for ${fileName}:`, mammothError);
            console.error(`Error type: ${mammothError.constructor.name}`);
            console.error(`Error stack: ${mammothError.stack}`);

            // Check if this is a legacy DOC format that we can try with alternative approach
            if (isLegacyDoc && fileExtension === 'doc') {
                console.log(`Attempting alternative extraction method for legacy DOC: ${fileName}`);
                try {
                    // Try with simplified options for very old DOC formats
                    const simpleOptions = {
                        buffer: buffer
                    };
                    result = await mammoth.extractRawText(simpleOptions);
                    console.log(`Alternative extraction succeeded for ${fileName}`);
                } catch (alternativeError) {
                    console.error(`Alternative extraction also failed for ${fileName}:`, alternativeError);

                    // Return a more helpful error for legacy DOC files
                    return res.status(400).json({
                        error: 'Legacy DOC format not supported',
                        details: `The file "${fileName}" appears to be a very old Microsoft Word format (pre-Office 97) or uses proprietary features that are not supported. Please try: 1) Converting the file to DOCX format using a newer version of Microsoft Word, 2) Saving as RTF and then converting to DOCX, or 3) Using a PDF version of the document instead.`,
                        fileName: fileName,
                        fileAnalysis: {
                            extension: fileExtension,
                            isLegacyDoc: isLegacyDoc,
                            isDocx: isDocx,
                            bufferSize: buffer.length,
                            suggestedActions: [
                                "Convert to DOCX format using Microsoft Word",
                                "Save as RTF and then convert to DOCX", 
                                "Export as PDF and upload PDF instead"
                            ]
                        }
                    });
                }
            } else {
                // Detailed error analysis for other cases
                let errorCategory = 'unknown';
                let specificMessage = mammothError.message;

                if (mammothError.message.includes('timeout')) {
                    errorCategory = 'timeout';
                    specificMessage = `Document processing timed out. The file ${fileName} may be too large or complex.`;
                } else if (mammothError.message.includes('password') || mammothError.message.includes('encrypted')) {
                    errorCategory = 'encrypted';
                    specificMessage = `Document ${fileName} appears to be password-protected or encrypted.`;
                } else if (mammothError.message.includes('format') || mammothError.message.includes('not supported')) {
                    errorCategory = 'format';
                    specificMessage = `Document format not supported for ${fileName}. This may be a very old DOC format or corrupted file.`;
                } else if (mammothError.message.includes('corrupt') || mammothError.message.includes('damaged')) {
                    errorCategory = 'corrupt';
                    specificMessage = `Document ${fileName} appears to be corrupted or damaged.`;
                } else if (mammothError.message.includes('zip') || mammothError.message.includes('archive')) {
                    errorCategory = 'zip_error';
                    specificMessage = `DOCX format parsing failed for ${fileName}. The document may be corrupted or use an unsupported variant.`;
                } else if (mammothError.message.includes('OLE') || mammothError.message.includes('compound')) {
                    errorCategory = 'ole_error';
                    specificMessage = `Legacy DOC format parsing failed for ${fileName}. This may be a very old or proprietary DOC format.`;
                }

                console.error(`Error category: ${errorCategory}`);

                throw new Error(`${specificMessage} (Category: ${errorCategory}, Original: ${mammothError.message})`);
            }
        }

        let text = result.value || '';

        // Log any conversion messages/warnings from mammoth
        if (result.messages && result.messages.length > 0) {
            console.log(`Mammoth conversion messages for ${fileName}:`);
            result.messages.forEach((msg, idx) => {
                console.log(`  ${idx + 1}. ${msg.type}: ${msg.message}`);
            });
        }

        console.log(`Raw extracted text length: ${text.length}`);
        if (text.length > 0) {
            console.log(`Raw text preview (first 500 chars): ${text.substring(0, 500)}`);
        }

        // Enhanced text cleaning
        text = text
            .replace(/\r\n/g, '\n')           // Normalize Windows line endings
            .replace(/\r/g, '\n')             // Handle old Mac line endings
            .replace(/\n\s*\n+/g, '\n\n')     // Remove excessive newlines but keep paragraph breaks
            .replace(/[ \t]+/g, ' ')          // Normalize spaces and tabs
            .replace(/\u00A0/g, ' ')          // Replace non-breaking spaces
            .replace(/[\u2000-\u200B]/g, ' ') // Replace various Unicode spaces
            .trim();

        console.log(`Cleaned text length: ${text.length}`);
        if (text.length > 0) {
            console.log(`Cleaned text preview (first 500 chars): ${text.substring(0, 500)}`);
        }

        // More lenient text validation for older documents
        if (!text || text.trim().length < 5) {
            console.error(`Very short text extracted from ${fileName}: "${text}"`);
            console.error(`Document analysis - Extension: ${fileExtension}, Legacy DOC: ${isLegacyDoc}, DOCX: ${isDocx}`);

            return res.status(400).json({
                error: 'Document parsing failed',
                details: `Could not extract sufficient text from "${fileName}". This may be due to: 1) Very old DOC format not fully supported, 2) Document contains only images/tables, 3) Password protection, or 4) File corruption. Extracted ${text.length} characters.`,
                fileName: fileName,
                fileAnalysis: {
                    extension: fileExtension,
                    isLegacyDoc: isLegacyDoc,
                    isDocx: isDocx,
                    bufferSize: buffer.length,
                    extractedLength: text.length
                }
            });
        }

        console.log(`Successfully extracted ${text.length} characters from Word document: ${fileName}`);
        res.json({ 
            text: text,
            originalLength: result.value ? result.value.length : 0,
            messages: result.messages || [],
            extractedLength: text.length,
            fileAnalysis: {
                extension: fileExtension,
                isLegacyDoc: isLegacyDoc,
                isDocx: isDocx,
                bufferSize: buffer.length
            }
        });

    } catch (error) {
        console.error(`=== Word document extraction failed for ${req.body?.fileName || 'unknown'} ===`);
        console.error('Error details:', error);
        console.error('Error type:', error.constructor.name);
        console.error('Error stack:', error.stack);

        // Log request details for debugging
        if (req.body) {
            console.error('Request analysis:');
            console.error(`  - File name: ${req.body.fileName || 'not provided'}`);
            console.error(`  - File data length: ${req.body.fileData ? req.body.fileData.length : 'not provided'}`);
        }

        // Categorized error responses
        let errorDetails = error.message;
        let statusCode = 500;

        if (error.message.includes('base64') || error.message.includes('Buffer')) {
            statusCode = 400;
            errorDetails = 'Invalid file encoding. Please ensure the file is properly uploaded.';
        } else if (error.message.includes('password') || error.message.includes('encrypted')) {
            statusCode = 400;
            errorDetails = 'Document appears to be password-protected. Please provide an unprotected version.';
        } else if (error.message.includes('format') || error.message.includes('not supported')) {
            statusCode = 400;
            errorDetails = `Document format issue. ${error.message}`;
        } else if (error.message.includes('timeout')) {
            statusCode = 408;
            errorDetails = 'Document processing timed out. Please try with a smaller or simpler document.';
        } else if (error.message.includes('corrupt') || error.message.includes('damaged')) {
            statusCode = 400;
            errorDetails = 'Document appears to be corrupted or damaged.';
        }

        res.status(statusCode).json({
            error: 'Word document extraction failed',
            details: errorDetails,
            fileName: req.body?.fileName || 'unknown',
            originalError: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// Extract key data from resume using GPT-4o-mini
app.post('/api/extract-resume-data', requireApiKey, async (req, res) => {
    try {
        const { resumeText, resumeName } = req.body;

        if (!resumeText || !resumeName) {
            return res.status(400).json({
                error: 'Missing required fields',
                details: 'resumeText and resumeName are required'
            });
        }

        console.log(`Extracting data from resume: ${resumeName}`);
        console.log(`Resume text length: ${resumeText.length} characters`);

        const prompt = `Extract key information from this resume. Return only a valid JSON object with no additional text.

Resume Text:
${resumeText}

Return JSON in this exact format:
{
  "name": "candidate name",
  "technical_skills": ["skill1", "skill2"],
  "experience_years": "X years",
  "work_experience": ["job1 description", "job2 description"],
  "education": ["degree1", "degree2"],
  "certifications": ["cert1", "cert2"],
  "soft_skills": ["skill1", "skill2"],
  "industry_experience": ["industry1", "industry2"],
  "key_achievements": ["achievement1", "achievement2"],
  "tools_technologies": ["tool1", "tool2"]
}`;

        const fullPrompt = `You are an expert resume parser. Extract key information from resumes and return only valid JSON with no additional text or formatting.

${prompt}`;

        const content = await makeOpenRouterRequest(fullPrompt, 0.1);
        console.log(`Raw content from OpenRouter for ${resumeName}:`, content);

        // Try to parse the JSON directly first
        let resumeData;
        try {
            resumeData = JSON.parse(content);
        } catch (parseError) {
            // If direct parsing fails, try to extract JSON from the response
            const jsonMatch = content.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                resumeData = JSON.parse(jsonMatch[0]);
            } else {
                throw new Error('Could not parse JSON from OpenRouter response: ' + content);
            }
        }

        resumeData.original_filename = resumeName;
        console.log(`Parsed resume data for ${resumeName}:`, resumeData);
        res.json(resumeData);

    } catch (error) {
        console.error(`Resume data extraction failed for ${resumeName}:`, error);
        res.status(500).json({
            error: 'Resume data extraction failed',
            details: error.message,
            resumeName: resumeName
        });
    }
});

app.post('/api/analyze', requireApiKey, async (req, res) => {
    try {
        const { jobRequirements, resumeDataList, additionalCriteria } = req.body;

        if (!jobRequirements || !resumeDataList || !Array.isArray(resumeDataList)) {
            return res.status(400).json({
                error: 'Invalid request data',
                details: 'jobRequirements and resumeDataList (array) are required'
            });
        }

        console.log('Starting final analysis...');
        console.log('Job requirements:', jobRequirements);
        console.log('Number of resumes to analyze:', resumeDataList.length);

        const prompt = `You are an expert HR analyst conducting detailed resume evaluation. Analyze each candidate systematically against the job requirements and return ONLY a valid JSON array.

CRITICAL EVALUATION FRAMEWORK:
Score candidates based on EXACT requirement matches:
- 95-100%: Perfect match - meets ALL requirements + exceptional extras
- 85-94%: Excellent match - meets all core requirements + most preferred
- 75-84%: Very good match - meets all core requirements, some preferred missing
- 65-74%: Good match - meets most core requirements, gaps in preferred areas
- 55-64%: Moderate match - meets some core requirements, significant gaps
- 45-54%: Weak match - limited requirement alignment
- Below 45%: Poor match - major misalignment with core requirements

JOB REQUIREMENTS TO MATCH AGAINST:
${JSON.stringify(jobRequirements, null, 2)}

${additionalCriteria ? `\nADDITIONAL HR CRITERIA (HIGH PRIORITY):
${additionalCriteria}` : ''}

SYSTEMATIC EVALUATION PROCESS:
For each candidate, analyze:
1. TECHNICAL SKILLS (35%): Direct match between candidate's technical_skills/tools_technologies and job technical_skills
2. EXPERIENCE MATCH (30%): Compare experience_years and work_experience against job experience_requirements
3. INDUSTRY ALIGNMENT (20%): Match industry_experience with job industry_experience requirements
4. EDUCATION/CERTS (10%): Compare education/certifications with job education_requirements and certifications
5. SOFT SKILLS (5%): Alignment of soft_skills with job soft_skills requirements

CANDIDATES TO EVALUATE:
${resumeDataList.map((resume, idx) => `
=== CANDIDATE ${idx + 1}: ${resume.original_filename} ===
Name: ${resume.name || 'Not specified'}
Technical Skills: ${JSON.stringify(resume.technical_skills || [])}
Tools/Technologies: ${JSON.stringify(resume.tools_technologies || [])}
Experience: ${resume.experience_years || 'Not specified'}
Work Experience: ${JSON.stringify(resume.work_experience || [])}
Education: ${JSON.stringify(resume.education || [])}
Certifications: ${JSON.stringify(resume.certifications || [])}
Industry Experience: ${JSON.stringify(resume.industry_experience || [])}
Soft Skills: ${JSON.stringify(resume.soft_skills || [])}
Key Achievements: ${JSON.stringify(resume.key_achievements || [])}
`).join('\n\n')}

RETURN FORMAT (MUST BE VALID JSON ARRAY):
[
  {
    "name": "exact original filename",
    "score": numeric_score,
    "reasoning": "Detailed 2-3 sentence analysis explaining the score based on requirement matches and gaps",
    "strengths": ["specific matched requirement 1", "specific matched requirement 2", "specific matched requirement 3"],
    "weaknesses": ["specific missing requirement 1", "specific gap 2", "specific concern 3"]
  }
]

IMPORTANT: 
- Be PRECISE with scoring - only high scores for candidates who truly match requirements
- Focus on ACTUAL requirement matches, not general qualifications
- Sort by score from highest to lowest
- Ensure all scores reflect real alignment with job requirements`;

        const fullPrompt = `You are an expert HR analyst. Analyze resumes against job descriptions and return only valid JSON arrays with no additional text or formatting.

${prompt}`;

        const content = await makeOpenRouterRequest(fullPrompt, 0.3);
        console.log('Raw analysis content from OpenRouter:', content);

        // Try to parse the JSON directly first
        let results;
        try {
            results = JSON.parse(content);
        } catch (parseError) {
            // If direct parsing fails, try to extract JSON array from the response
            const jsonMatch = content.match(/\[[\s\S]*\]/);
            if (jsonMatch) {
                results = JSON.parse(jsonMatch[0]);
            } else {
                throw new Error('Could not parse JSON array from OpenRouter response: ' + content);
            }
        }

        if (!Array.isArray(results)) {
            throw new Error('OpenRouter response is not a valid array');
        }

        // Validate analysis results
        const validatedResults = results.map(result => ({
            name: result.name || 'Unknown',
            score: Math.min(Math.max(parseInt(result.score) || 0, 0), 100), // Ensure score is 0-100
            reasoning: result.reasoning || 'No analysis provided',
            strengths: Array.isArray(result.strengths) ? result.strengths.slice(0, 5) : [], // Limit to 5 strengths
            weaknesses: Array.isArray(result.weaknesses) ? result.weaknesses.slice(0, 5) : [] // Limit to 5 weaknesses
        }));

        // Sort by score to ensure proper ranking
        validatedResults.sort((a, b) => b.score - a.score);

        console.log('Validated analysis results:', validatedResults);
        res.json(validatedResults);

    } catch (error) {
        console.error('Analysis failed:', error);
        res.status(500).json({
            error: 'Analysis failed',
            details: error.message
        });
    }
});

app.post('/api/send-email', async (req, res) => {
    try {
        const { to, subject, message, reportData } = req.body;

        if (!to || !subject) {
            return res.status(400).json({ error: 'Email address and subject are required' });
        }

        if (!SENDGRID_API_KEY) {
            return res.status(500).json({
                error: 'SendGrid API key not configured',
                details: 'Please add SENDGRID_API_KEY to your Replit Secrets'
            });
        }

        // Generate HTML content for the email
        const htmlContent = generateEmailHTML(reportData, message);

        const msg = {
            to: to,
            from: SENDGRID_FROM_EMAIL,
            subject: subject,
            text: message || 'Please find the attached resume analysis report.',
            html: htmlContent,
        };

        await sgMail
            .send(msg)
            .then(() => {
                console.log('Email sent successfully');
                res.json({ success: true, message: 'Email sent successfully' });
            })
            .catch((error) => {
                console.error('SendGrid error:', error);
                throw error;
            });

    } catch (error) {
        console.error('Email sending failed:', error);

        // Handle specific SendGrid errors
        if (error.response && error.response.body) {
            console.error('SendGrid error details:', error.response.body);
            return res.status(500).json({
                error: 'SendGrid API error',
                details: error.response.body.errors ? error.response.body.errors[0].message : 'Unknown SendGrid error'
            });
        }

        return res.status(500).json({
            error: 'Failed to send email',
            details: error.message
        });
    }
});

function generateEmailHTML(reportData, customMessage) {
    if (!reportData || !Array.isArray(reportData)) {
        return `
            <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <h2 style="color: #1a237e;">Resume Analysis Report</h2>
                    <p>${customMessage || 'Please find the resume analysis report attached.'}</p>
                    <p>Generated on: ${new Date().toLocaleDateString()}</p>
                    <hr style="border: 1px solid #eee; margin: 20px 0;">
                    <p style="color: #666; font-size: 0.9em;">This report was generated by Resume Matcher AI tool.</p>
                </body>
            </html>
        `;
    }

    const resultsHTML = reportData.map((result, index) => `
        <div style="margin-bottom: 25px; padding: 20px; border: 1px solid #ddd; border-radius: 8px; background-color: #f9f9f9;">
            <h3 style="color: #1a237e; margin-top: 0;">
                ${index + 1}. ${result.name}
                <span style="float: right; background: ${result.score >= 80 ? '#28a745' : result.score >= 60 ? '#ffc107' : '#dc3545'};
                color: white; padding: 5px 15px; border-radius: 20px; font-size: 0.9em;">
                    ${result.score}%
                </span>
            </h3>
            <p><strong>Analysis:</strong> ${result.reasoning}</p>
            <p><strong>Strengths:</strong> ${result.strengths.join(', ')}</p>
            ${result.weaknesses && result.weaknesses.length > 0 ?
                `<p><strong>Areas for consideration:</strong> ${result.weaknesses.join(', ')}</p>` : ''}
        </div>
    `).join('');

    return `
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #1a237e; text-align: center; border-bottom: 3px solid #1a237e; padding-bottom: 10px;">
                    Resume Analysis Report
                </h1>
                <p style="background-color: #f0f4ff; padding: 15px; border-radius: 5px; border-left: 4px solid #1a237e;">
                    ${customMessage || 'Please find the detailed resume analysis report below.'}
                </p>
                <p><strong>Generated on:</strong> ${new Date().toLocaleDateString()} at ${new Date().toLocaleTimeString()}</p>
                <p><strong>Total Candidates Analyzed:</strong> ${reportData.length}</p>

                <h2 style="color: #1a237e; margin-top: 30px;">Candidate Rankings</h2>
                ${resultsHTML}

                <hr style="border: 1px solid #eee; margin: 30px 0;">
                <p style="color: #666; font-size: 0.9em; text-align: center;">
                    This report was generated by Resume Matcher AI-powered recruitment tool.<br>
                    Rankings are based on AI analysis and should be used as a guideline alongside human judgment.
                </p>
            </body>
        </html>
    `;
}



const DEFAULT_PORT = parseInt(process.env.PORT, 10) || 3000;
const HOST = '0.0.0.0';

function startServer(port, attempts = 5) {
    const server = app.listen(port, HOST, async () => {
        console.log(`Server running on port ${port}`);
        console.log(`Server accessible at: http://${HOST}:${port}`);

        // Initialize database
        if (DATABASE_URL) {
            console.log('🗄️ Initializing database...');
            await initializeDatabase();
        } else {
            console.error('❌ DATABASE_URL is not set. Please add a PostgreSQL database in Replit.');
        }

        // Check if API key is configured
        if (!OPENROUTER_API_KEY) {
            console.error('❌ OPENROUTER_API_KEY is not set in environment variables');
            console.log('Please add your OpenRouter API key to Replit Secrets');
        } else {
            console.log('✅ OpenRouter API key is configured');

            // Query available models on startup
            console.log('🔍 Querying available OpenRouter models...');
            await queryAvailableModels();
        }
    });

    server.on('error', (err) => {
        if (err.code === 'EADDRINUSE' && attempts > 0) {
            console.warn(`Port ${port} in use. Trying ${port + 1}...`);
            setTimeout(() => startServer(port + 1, attempts - 1), 500);
        } else {
            console.error('Failed to start server:', err);
            process.exit(1);
        }
    });

    process.on('SIGTERM', () => server.close(() => process.exit(0)));
    process.on('SIGINT', () => server.close(() => process.exit(0)));
}

startServer(DEFAULT_PORT);