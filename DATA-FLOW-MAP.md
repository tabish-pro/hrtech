# Lamprell Resume Analyzer - Data Flow Map

**Document Version:** 1.0
**Last Updated:** 2025-12-10
**Application:** HR Resume Analyzer (AI-Powered Recruitment Tool)

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Architecture Diagram](#architecture-diagram)
3. [Component Architecture](#component-architecture)
4. [Data Flow Patterns](#data-flow-patterns)
5. [Authentication & Authorization Flow](#authentication--authorization-flow)
6. [Resume Analysis Pipeline](#resume-analysis-pipeline)
7. [User Management Flow](#user-management-flow)
8. [Email Report Flow](#email-report-flow)
9. [External API Integration](#external-api-integration)
10. [Data Models](#data-models)
11. [Security & Rate Limiting](#security--rate-limiting)
12. [Error Handling Flow](#error-handling-flow)

---

## System Overview

The Lamprell Resume Analyzer is a full-stack web application that leverages AI to analyze and rank candidate resumes against job descriptions. It is designed for internal HR/recruitment teams to streamline candidate evaluation.

### Technology Stack

**Frontend:**
- Vanilla JavaScript (ES6+)
- HTML5 with CSS3 animations
- PDF.js (client-side text extraction)
- Font Awesome 6.0.0 (icons)

**Backend:**
- Node.js 18 (Alpine)
- Express.js 4.18.2
- PostgreSQL 13 (pg v8.11.3)
- bcrypt v5.1.1 (password security)
- Mammoth.js v1.9.1 (Word document processing)

**Infrastructure:**
- Docker & Docker Compose
- Nginx (reverse proxy with SSL/TLS)
- Self-signed SSL certificates

**External Services:**
- OpenRouter API (GPT-4o-mini for AI analysis)
- SendGrid API (email delivery)

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                           USER BROWSER                           │
│  ┌────────────────────┐              ┌────────────────────┐     │
│  │   login.html       │              │   index.html       │     │
│  │   (Authentication) │              │   (Main App)       │     │
│  └────────────────────┘              └────────────────────┘     │
│           │                                    │                 │
│           │ Session Storage (isLoggedIn,       │                 │
│           │ username, isAdmin, userId)         │                 │
│           └────────────────────────────────────┘                 │
│                            │                                     │
│                      HTTPS (Port 443)                            │
└────────────────────────────┼────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      NGINX REVERSE PROXY                         │
│  • SSL/TLS Termination (Self-signed certificates)               │
│  • HTTP → HTTPS Redirect (Port 80 → 443)                        │
│  • Security Headers (HSTS, X-Frame-Options, etc.)               │
│  • Proxy to backend on port 3000                                │
│  • 300s timeout for large uploads                               │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    NODE.JS EXPRESS BACKEND                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Authentication Module                                     │  │
│  │  • POST /api/login                                        │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │  User Management Module (Admin)                           │  │
│  │  • GET /api/users                                         │  │
│  │  • POST /api/users                                        │  │
│  │  • PUT /api/users/:id/password                            │  │
│  │  • DELETE /api/users/:id                                  │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │  Document Processing Module                               │  │
│  │  • POST /api/extract-word-text                            │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │  AI Analysis Module                                       │  │
│  │  • POST /api/extract-job-requirements                     │  │
│  │  • POST /api/extract-resume-data                          │  │
│  │  • POST /api/analyze                                      │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │  Email Service Module                                     │  │
│  │  • POST /api/send-email                                   │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │  Rate Limiting Middleware                                 │  │
│  │  • Max 3 concurrent requests per IP                       │  │
│  │  • Min 1 second between requests                          │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────────────┬──────────────────────────────┬───────────────────┘
               │                              │
               ▼                              ▼
┌──────────────────────────────┐  ┌──────────────────────────────┐
│     POSTGRESQL DATABASE      │  │    EXTERNAL APIS             │
│  ┌────────────────────────┐  │  │  ┌────────────────────────┐ │
│  │  users table           │  │  │  │  OpenRouter API        │ │
│  │  • id (PK)             │  │  │  │  (GPT-4o-mini)         │ │
│  │  • username (UNIQUE)   │  │  │  │  openrouter.ai         │ │
│  │  • password_hash       │  │  │  └────────────────────────┘ │
│  │  • is_admin            │  │  │  ┌────────────────────────┐ │
│  │  • created_at          │  │  │  │  SendGrid API          │ │
│  │  • created_by          │  │  │  │  (Email delivery)      │ │
│  │  • last_login          │  │  │  │  api.sendgrid.com      │ │
│  └────────────────────────┘  │  │  └────────────────────────┘ │
└──────────────────────────────┘  └──────────────────────────────┘
```

---

## Component Architecture

### Frontend Components

#### 1. Authentication UI ([login.html])
- **Responsibility:** User authentication interface
- **Data Input:** Username, password
- **Data Output:** Session credentials stored in sessionStorage
- **Navigation:** Redirects to [index.html] on success

#### 2. Main Application UI ([index.html])
- **Components:**
  - Job Description Upload Area
  - Resume Upload Area (batch)
  - Settings Panel (additional criteria)
  - User Management Modal (admin only)
  - Results Display Area
  - Export Controls (PDF, CSV, Email)
- **Session Check:** Redirects to login if not authenticated

#### 3. Client-Side Script ([public/script.js])
- **Lines of Code:** 1,909
- **Key Functions:**
  - File upload and validation
  - PDF text extraction (PDF.js)
  - Word document conversion to base64
  - Progress tracking and UI updates
  - Results rendering
  - Export functionality (PDF/CSV generation)
  - User management operations

### Backend Components

#### 1. Main Server ([server.js])
- **Lines of Code:** 1,184
- **Framework:** Express.js
- **Port:** 3000 (internal)
- **Database Connection:** PostgreSQL via pg pool
- **Middleware:**
  - express.json() with 50MB limit
  - CORS enabled
  - Rate limiting per IP

#### 2. Authentication Module
- **Endpoints:**
  - `POST /api/login`
- **Security:** bcrypt password hashing (10 salt rounds)
- **Session:** Returns user object for client-side session management

#### 3. User Management Module
- **Endpoints:**
  - `GET /api/users` (admin only)
  - `POST /api/users` (admin only, max 5 non-admin users)
  - `PUT /api/users/:id/password` (admin only)
  - `DELETE /api/users/:id` (admin only, cannot delete admin)
- **Authorization:** Hardcoded check for 'hradmin' username

#### 4. Document Processing Module
- **Endpoints:**
  - `POST /api/extract-word-text`
- **Library:** Mammoth.js
- **Validation:**
  - DOCX format only
  - Max 10MB file size
  - 45-second timeout
- **Error Handling:** Categorized error messages for legacy DOC formats

#### 5. AI Analysis Module
- **Endpoints:**
  - `POST /api/extract-job-requirements`
  - `POST /api/extract-resume-data`
  - `POST /api/analyze`
- **AI Provider:** OpenRouter API
- **Model:** openai/gpt-4o-mini
- **Scoring Framework:**
  - 95-100%: Perfect match
  - 85-94%: Excellent match
  - 75-84%: Very good match
  - 65-74%: Good match
  - 55-64%: Moderate match
  - 45-54%: Weak match
  - <45%: Poor match
- **Evaluation Weights:**
  - Technical Skills: 35%
  - Experience Match: 30%
  - Industry Alignment: 20%
  - Education/Certifications: 10%
  - Soft Skills: 5%

#### 6. Email Service Module
- **Endpoints:**
  - `POST /api/send-email`
- **Provider:** SendGrid API
- **Functionality:** Generates HTML email reports and sends to recipients

### Infrastructure Components

#### 1. Nginx Reverse Proxy
- **Configuration File:** [nginx/nginx.conf]
- **Functions:**
  - SSL/TLS termination
  - HTTP to HTTPS redirect
  - Request proxying to backend
  - Security headers injection
  - WebSocket support
- **Ports:**
  - 80 (HTTP → redirect)
  - 443 (HTTPS)

#### 2. PostgreSQL Database
- **Version:** 13-alpine
- **Container Name:** hrtech_db
- **Port:** 5432 (internal)
- **Schema:** Single table (users)
- **Initialization:** Auto-creates schema and default admin user on startup

#### 3. Docker Network
- **Name:** hrtech-network
- **Type:** Bridge
- **Services:**
  - hrtech_app (Node.js backend)
  - hrtech_db (PostgreSQL)
  - hrtech_nginx (reverse proxy)

---

## Data Flow Patterns

### 1. User Authentication Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER BROWSER                             │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               │ 1. User enters credentials
                               │    (username, password)
                               ▼
                    ┌──────────────────────┐
                    │   login.html         │
                    │   - Validate inputs  │
                    │   - POST request     │
                    └──────────┬───────────┘
                               │
                               │ 2. POST /api/login
                               │    Body: { username, password }
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                      EXPRESS BACKEND                             │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Authentication Endpoint Handler                         │   │
│  │  1. Receive credentials                                  │   │
│  │  2. Query PostgreSQL for username                        │   │
│  │  3. bcrypt.compare(password, password_hash)              │   │
│  │  4. If valid: return user object                         │   │
│  │     { id, username, isAdmin }                            │   │
│  │  5. Update last_login timestamp                          │   │
│  └────────────────┬─────────────────────────────────────────┘   │
└───────────────────┼─────────────────────────────────────────────┘
                    │
                    │ 3. Query database
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                    POSTGRESQL DATABASE                           │
│  SELECT * FROM users WHERE username = $1                         │
│  Returns: { id, username, password_hash, is_admin, ... }         │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     │ 4. Database response
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                      EXPRESS BACKEND                             │
│  bcrypt.compare(inputPassword, storedHash)                       │
│  ✓ Match: return 200 with user object                           │
│  ✗ No match: return 401                                          │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     │ 5. Response: { success: true, user: {...} }
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                         USER BROWSER                             │
│  1. Store in sessionStorage:                                     │
│     - isLoggedIn: 'true'                                         │
│     - username: 'john.doe'                                       │
│     - isAdmin: 'false'                                           │
│     - userId: '123'                                              │
│  2. Redirect to index.html                                       │
└─────────────────────────────────────────────────────────────────┘
```

**Key Points:**
- Password never stored in plain text
- bcrypt provides one-way hashing with salt
- Session data stored client-side (volatile, cleared on browser close)
- last_login timestamp updated on successful authentication

---

### 2. Resume Analysis Pipeline (Main Data Flow)

```
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: JOB DESCRIPTION UPLOAD                                  │
└──────────────────────────────────────────────────────────────────┘
                               │
         User uploads job description (PDF or DOCX)
                               │
                               ▼
                    ┌──────────────────────┐
                    │  File Validation     │
                    │  - Check extension   │
                    │  - Check size <10MB  │
                    └──────────┬───────────┘
                               │
                               ▼
              ┌────────────────┴────────────────┐
              │                                 │
        PDF format?                       DOCX format?
              │                                 │
              ▼                                 ▼
   ┌────────────────────┐          ┌────────────────────┐
   │ Client-side        │          │ Server-side        │
   │ PDF.js extracts    │          │ 1. Convert to      │
   │ text page by page  │          │    base64          │
   │ (max 100 pages,    │          │ 2. POST            │
   │  20s timeout)      │          │    /api/extract-   │
   └──────────┬─────────┘          │    word-text       │
              │                    │ 3. Mammoth.js      │
              │                    │    extracts text   │
              │                    └──────────┬─────────┘
              │                               │
              └───────────────┬───────────────┘
                              │
                   Extracted Job Description Text
                              │
┌─────────────────────────────────────────────────────────────────┐
│ STEP 2: JOB REQUIREMENTS EXTRACTION                             │
└──────────────────────────────────────────────────────────────────┘
                              │
                              │ POST /api/extract-job-requirements
                              │ Body: { jobDescription: "text..." }
                              ▼
                    ┌──────────────────────┐
                    │ Express Backend      │
                    │ Rate Limit Check     │
                    └──────────┬───────────┘
                               │
                               │ OpenRouter API Request
                               ▼
                    ┌──────────────────────┐
                    │  OpenRouter API      │
                    │  Model: GPT-4o-mini  │
                    │  Temperature: 0.1    │
                    │  Timeout: 60s        │
                    └──────────┬───────────┘
                               │
                               │ AI extracts structured requirements
                               ▼
              ┌─────────────────────────────────────┐
              │  Job Requirements Object            │
              │  {                                  │
              │    technical_skills: [],            │
              │    experience_requirements: [],     │
              │    education_requirements: [],      │
              │    soft_skills: [],                 │
              │    industry_experience: [],         │
              │    certifications: [],              │
              │    additional_requirements: []      │
              │  }                                  │
              └─────────────────┬───────────────────┘
                                │
                   Stored in browser memory
                                │
┌─────────────────────────────────────────────────────────────────┐
│ STEP 3: RESUME UPLOAD (BATCH)                                   │
└──────────────────────────────────────────────────────────────────┘
                                │
      User uploads multiple resumes (up to 500, recommend 200)
                                │
                                ▼
                     ┌──────────────────────┐
                     │  File Validation     │
                     │  - Check extensions  │
                     │  - Check sizes       │
                     │  - Track progress    │
                     └──────────┬───────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│ STEP 4: TEXT EXTRACTION (FOR EACH RESUME)                       │
└──────────────────────────────────────────────────────────────────┘
                                │
                                │ For each resume file:
                                ▼
              ┌─────────────────┴──────────────────┐
              │                                    │
        PDF format?                          DOCX format?
              │                                    │
              ▼                                    ▼
   ┌────────────────────┐           ┌────────────────────┐
   │ Client-side        │           │ Server-side        │
   │ PDF.js extraction  │           │ POST               │
   │ (~3s per file)     │           │ /api/extract-word- │
   └──────────┬─────────┘           │ text               │
              │                     │ (~3s per file)     │
              │                     └──────────┬─────────┘
              │                                │
              └────────────────┬───────────────┘
                               │
                    Extracted Resume Text
                               │
                               │ Progress: (current / total)
                               │ Est. time: N resumes × 3s
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 5: RESUME DATA EXTRACTION (FOR EACH RESUME)                │
└──────────────────────────────────────────────────────────────────┘
                               │
                               │ POST /api/extract-resume-data
                               │ Body: { resumeText: "...", filename: "..." }
                               ▼
                    ┌──────────────────────┐
                    │ Express Backend      │
                    │ Rate Limit Check     │
                    └──────────┬───────────┘
                               │
                               │ OpenRouter API Request (~2.5s)
                               ▼
                    ┌──────────────────────┐
                    │  OpenRouter API      │
                    │  Model: GPT-4o-mini  │
                    │  Temperature: 0.1    │
                    │  Timeout: 60s        │
                    └──────────┬───────────┘
                               │
                               │ AI extracts structured data
                               ▼
              ┌─────────────────────────────────────┐
              │  Resume Data Object                 │
              │  {                                  │
              │    original_filename: "resume.pdf", │
              │    name: "John Doe",                │
              │    technical_skills: [],            │
              │    experience_years: "5 years",     │
              │    work_experience: [],             │
              │    education: [],                   │
              │    certifications: [],              │
              │    soft_skills: [],                 │
              │    industry_experience: [],         │
              │    key_achievements: [],            │
              │    tools_technologies: []           │
              │  }                                  │
              └─────────────────┬───────────────────┘
                                │
                   Collected in array: resumeDataList[]
                                │
                   Progress: (current / total)
                   Est. time: N resumes × 2.5s
                                │
┌─────────────────────────────────────────────────────────────────┐
│ STEP 6: BATCH ANALYSIS & RANKING                                │
└──────────────────────────────────────────────────────────────────┘
                                │
                                │ POST /api/analyze
                                │ Body: {
                                │   jobRequirements: {...},
                                │   resumeData: [{...}, {...}, ...],
                                │   additionalCriteria: {...}
                                │ }
                                ▼
                    ┌──────────────────────┐
                    │ Express Backend      │
                    │ Rate Limit Check     │
                    └──────────┬───────────┘
                               │
                               │ OpenRouter API Request
                               │ (~0.5s per resume, scaled)
                               ▼
                    ┌──────────────────────┐
                    │  OpenRouter API      │
                    │  Model: GPT-4o-mini  │
                    │  Temperature: 0.3    │
                    │  Timeout: 60s        │
                    │  Max Tokens: 6000    │
                    └──────────┬───────────┘
                               │
                               │ AI scores and ranks all resumes
                               ▼
              ┌─────────────────────────────────────┐
              │  Analysis Results Array             │
              │  [                                  │
              │    {                                │
              │      name: "resume1.pdf",           │
              │      score: 92,                     │
              │      reasoning: "...",              │
              │      strengths: [...],              │
              │      weaknesses: [...]              │
              │    },                               │
              │    { ... },                         │
              │    ...                              │
              │  ]                                  │
              │  Sorted by score (descending)       │
              └─────────────────┬───────────────────┘
                                │
                   Response to frontend
                                │
┌─────────────────────────────────────────────────────────────────┐
│ STEP 7: RESULTS DISPLAY & EXPORT                                │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                     ┌──────────────────────┐
                     │  Frontend Rendering  │
                     │  1. Summary table    │
                     │  2. Detailed cards   │
                     │  3. Export buttons   │
                     └──────────┬───────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
              ▼                 ▼                 ▼
    ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
    │ PDF Report  │   │ CSV Export  │   │ Email Report│
    │ (client-    │   │ (client-    │   │ (SendGrid   │
    │  generated) │   │  generated) │   │  API)       │
    └─────────────┘   └─────────────┘   └─────────────┘
```

**Performance Metrics:**
- Job description extraction: ~2-5 seconds
- Resume text extraction: ~3 seconds per file
- Resume data parsing: ~2.5 seconds per file
- Batch analysis: ~0.5 seconds per resume (scaled)
- Total for 10 resumes: ~60-70 seconds
- Total for 100 resumes: ~550-600 seconds (~10 minutes)

**Parallelization:**
- Text extraction: Sequential (client-side for PDF, server API for DOCX)
- Data extraction: Sequential (rate-limited API calls)
- Analysis: Batch processing in single API call

---

### 3. User Management Flow (Admin Only)

```
┌─────────────────────────────────────────────────────────────────┐
│                    ADMIN USER BROWSER                            │
│  Session: username='hradmin', isAdmin='true'                     │
└──────────────────────────────────┬──────────────────────────────┘
                                   │
                     User clicks "User Management"
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │  Open Modal          │
                        │  1. Create New User  │
                        │  2. View Users       │
                        │  3. Edit/Delete      │
                        └──────────┬───────────┘
                                   │
┌──────────────────────────────────────────────────────────────────┐
│ ACTION 1: VIEW ALL USERS                                         │
└──────────────────────────────────────────────────────────────────┘
                                   │
                                   │ GET /api/users
                                   ▼
                        ┌──────────────────────┐
                        │ Express Backend      │
                        │ Check: username ==   │
                        │        'hradmin'     │
                        └──────────┬───────────┘
                                   │
                                   │ Query PostgreSQL
                                   ▼
                        ┌──────────────────────┐
                        │  PostgreSQL          │
                        │  SELECT * FROM users │
                        └──────────┬───────────┘
                                   │
                                   │ Return user list
                                   ▼
                        ┌──────────────────────────────┐
                        │  User List Array             │
                        │  [{                          │
                        │    id: 1,                    │
                        │    username: "hradmin",      │
                        │    is_admin: true,           │
                        │    created_at: "...",        │
                        │    created_by: null,         │
                        │    last_login: "..."         │
                        │  }, ...]                     │
                        └──────────┬───────────────────┘
                                   │
                                   │ Render in UI
                                   ▼
                        ┌──────────────────────┐
                        │  User List Display   │
                        │  - Username          │
                        │  - Admin status      │
                        │  - Created date      │
                        │  - Last login        │
                        │  - Actions (edit/del)│
                        └──────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ ACTION 2: CREATE NEW USER                                        │
└──────────────────────────────────────────────────────────────────┘
                                   │
         Admin fills form: username, password, confirmPassword
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │  Client Validation   │
                        │  1. Password regex   │
                        │  2. Match confirm    │
                        │  3. Length checks    │
                        └──────────┬───────────┘
                                   │
                                   │ POST /api/users
                                   │ Body: { username, password }
                                   ▼
                        ┌──────────────────────────────┐
                        │  Express Backend             │
                        │  1. Check: username ==       │
                        │           'hradmin'          │
                        │  2. Password validation      │
                        │  3. Count non-admin users    │
                        │     (max 5 allowed)          │
                        └──────────┬───────────────────┘
                                   │
                                   │ If valid:
                                   │ bcrypt.hash(password, 10)
                                   ▼
                        ┌──────────────────────┐
                        │  PostgreSQL          │
                        │  INSERT INTO users   │
                        │  (username,          │
                        │   password_hash,     │
                        │   created_by)        │
                        │  VALUES (...)        │
                        └──────────┬───────────┘
                                   │
                                   │ RETURNING *
                                   ▼
                        ┌──────────────────────┐
                        │  Success Response    │
                        │  { message: "...",   │
                        │    user: {...} }     │
                        └──────────┬───────────┘
                                   │
                                   │ Refresh user list
                                   ▼
                        ┌──────────────────────┐
                        │  UI Update           │
                        │  - Show success      │
                        │  - Clear form        │
                        │  - Reload user list  │
                        └──────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ ACTION 3: CHANGE USER PASSWORD                                   │
└──────────────────────────────────────────────────────────────────┘
                                   │
            Admin clicks "Edit" on user row
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │  Password Modal      │
                        │  Input: newPassword  │
                        └──────────┬───────────┘
                                   │
                                   │ PUT /api/users/:id/password
                                   │ Body: { newPassword }
                                   ▼
                        ┌──────────────────────────────┐
                        │  Express Backend             │
                        │  1. Check: username ==       │
                        │           'hradmin'          │
                        │  2. Password validation      │
                        │  3. bcrypt.hash(newPass, 10) │
                        └──────────┬───────────────────┘
                                   │
                                   │ UPDATE users
                                   ▼
                        ┌──────────────────────┐
                        │  PostgreSQL          │
                        │  UPDATE users        │
                        │  SET password_hash   │
                        │  WHERE id = $1       │
                        └──────────┬───────────┘
                                   │
                                   │ Success
                                   ▼
                        ┌──────────────────────┐
                        │  UI Update           │
                        │  Show success alert  │
                        └──────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ ACTION 4: DELETE USER                                            │
└──────────────────────────────────────────────────────────────────┘
                                   │
           Admin clicks "Delete" on user row
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │  Confirmation Dialog │
                        │  "Are you sure?"     │
                        └──────────┬───────────┘
                                   │
                                   │ DELETE /api/users/:id
                                   ▼
                        ┌──────────────────────────────┐
                        │  Express Backend             │
                        │  1. Check: username ==       │
                        │           'hradmin'          │
                        │  2. Check: user != 'hradmin' │
                        │     (cannot delete admin)    │
                        └──────────┬───────────────────┘
                                   │
                                   │ DELETE FROM users
                                   ▼
                        ┌──────────────────────┐
                        │  PostgreSQL          │
                        │  DELETE FROM users   │
                        │  WHERE id = $1       │
                        └──────────┬───────────┘
                                   │
                                   │ Success
                                   ▼
                        ┌──────────────────────┐
                        │  UI Update           │
                        │  - Show success      │
                        │  - Reload user list  │
                        └──────────────────────┘
```

**Authorization Rules:**
- All user management endpoints require username === 'hradmin'
- Maximum 5 non-admin users allowed
- Cannot delete the 'hradmin' account
- Password must meet complexity requirements (8+ chars, uppercase, lowercase, digit, special)

---

### 4. Email Report Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER BROWSER                             │
│  Analysis results displayed                                      │
└──────────────────────────────────┬──────────────────────────────┘
                                   │
              User clicks "Email Report" button
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │  Email Modal Opens   │
                        │  Inputs:             │
                        │  - Recipient email   │
                        │  - Subject           │
                        │  - Custom message    │
                        └──────────┬───────────┘
                                   │
                     User fills form and clicks "Send"
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │  Client Validation   │
                        │  - Email format      │
                        │  - Required fields   │
                        └──────────┬───────────┘
                                   │
                                   │ POST /api/send-email
                                   │ Body: {
                                   │   recipientEmail: "...",
                                   │   subject: "...",
                                   │   customMessage: "...",
                                   │   reportData: [...]
                                   │ }
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                      EXPRESS BACKEND                             │
└──────────────────────────────────┬──────────────────────────────┘
                                   │
                                   ▼
                        ┌──────────────────────────────┐
                        │  generateEmailHTML()         │
                        │  - Header with branding      │
                        │  - Custom message section    │
                        │  - Summary statistics        │
                        │  - Candidate cards:          │
                        │    * Name & score            │
                        │    * Match level badge       │
                        │    * Reasoning               │
                        │    * Strengths (green)       │
                        │    * Weaknesses (orange)     │
                        │  - Footer with timestamp     │
                        └──────────┬───────────────────┘
                                   │
                                   │ HTML email content
                                   ▼
                        ┌──────────────────────────────┐
                        │  SendGrid API Request        │
                        │  - From: SENDGRID_FROM_EMAIL │
                        │  - To: recipient             │
                        │  - Subject: subject          │
                        │  - HTML content              │
                        └──────────┬───────────────────┘
                                   │
                                   │ POST to api.sendgrid.com
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                        SENDGRID API                              │
│  - Validates API key                                             │
│  - Validates recipient email                                     │
│  - Queues email for delivery                                     │
└──────────────────────────────────┬──────────────────────────────┘
                                   │
                                   │ Response
                                   ▼
                        ┌──────────────────────────────┐
                        │  Success or Error            │
                        │  - 200: Accepted             │
                        │  - 4xx/5xx: Error details    │
                        └──────────┬───────────────────┘
                                   │
                                   │ Response to frontend
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                         USER BROWSER                             │
│  - Show success/error alert                                      │
│  - Close modal on success                                        │
│  - Display error message on failure                              │
└─────────────────────────────────────────────────────────────────┘
```

**Email Report Contents:**
1. **Header:** Lamprell Resume Analyzer branding
2. **Custom Message:** User-provided introduction text
3. **Summary Statistics:**
   - Total candidates analyzed
   - Average match score
   - Top candidates count
4. **Candidate Cards:** For each resume:
   - Name and overall score
   - Match level badge (color-coded)
   - Detailed reasoning
   - Strengths (bullet points)
   - Weaknesses/gaps (bullet points)
5. **Footer:** Timestamp and system attribution

**Error Handling:**
- SendGrid API key validation
- Email format validation
- Network timeout handling
- Detailed error messages from SendGrid response

---

## External API Integration

### 1. OpenRouter API (AI Processing)

**Endpoint:** `https://openrouter.ai/api/v1/chat/completions`

**Authentication:**
```
Authorization: Bearer ${OPENROUTER_API_KEY}
HTTP-Referer: ${YOUR_SITE_URL}
X-Title: ${YOUR_SITE_NAME}
```

**Configuration:**
- **API Key Format:** Must start with "sk-or-" and be 20+ characters
- **Model:** openai/gpt-4o-mini
- **Timeout:** 60 seconds per request
- **Rate Limiting:** Enforced by OpenRouter account tier

**Request Flow:**

```
┌─────────────────────────────────────────────────────────────────┐
│ ENDPOINT 1: /api/extract-job-requirements                       │
└──────────────────────────────────────────────────────────────────┘

Express Backend → OpenRouter API

Request:
{
  "model": "openai/gpt-4o-mini",
  "temperature": 0.1,
  "messages": [{
    "role": "system",
    "content": "Extract requirements from job description..."
  }, {
    "role": "user",
    "content": "<job description text>"
  }]
}

Response:
{
  "choices": [{
    "message": {
      "content": "{
        \"technical_skills\": [...],
        \"experience_requirements\": [...],
        \"education_requirements\": [...],
        \"soft_skills\": [...],
        \"industry_experience\": [...],
        \"certifications\": [...],
        \"additional_requirements\": [...]
      }"
    }
  }]
}

┌─────────────────────────────────────────────────────────────────┐
│ ENDPOINT 2: /api/extract-resume-data                            │
└──────────────────────────────────────────────────────────────────┘

Express Backend → OpenRouter API

Request:
{
  "model": "openai/gpt-4o-mini",
  "temperature": 0.1,
  "messages": [{
    "role": "system",
    "content": "Extract structured data from resume..."
  }, {
    "role": "user",
    "content": "<resume text>"
  }]
}

Response:
{
  "choices": [{
    "message": {
      "content": "{
        \"name\": \"John Doe\",
        \"technical_skills\": [...],
        \"experience_years\": \"5 years\",
        \"work_experience\": [...],
        \"education\": [...],
        \"certifications\": [...],
        \"soft_skills\": [...],
        \"industry_experience\": [...],
        \"key_achievements\": [...],
        \"tools_technologies\": [...]
      }"
    }
  }]
}

┌─────────────────────────────────────────────────────────────────┐
│ ENDPOINT 3: /api/analyze                                        │
└──────────────────────────────────────────────────────────────────┘

Express Backend → OpenRouter API

Request:
{
  "model": "openai/gpt-4o-mini",
  "temperature": 0.3,
  "max_tokens": 6000,
  "messages": [{
    "role": "system",
    "content": "Analyze and rank candidates..."
  }, {
    "role": "user",
    "content": "Job: {...}, Resumes: [{...}, {...}], Criteria: {...}"
  }]
}

Response:
{
  "choices": [{
    "message": {
      "content": "[
        {
          \"name\": \"resume1.pdf\",
          \"score\": 92,
          \"reasoning\": \"Excellent match...\",
          \"strengths\": [...],
          \"weaknesses\": [...]
        },
        ...
      ]"
    }
  }]
}
```

**Error Handling:**
- Network timeouts (60s)
- Invalid API key
- Rate limit exceeded
- Malformed responses
- JSON parsing errors

---

### 2. SendGrid API (Email Delivery)

**Endpoint:** `https://api.sendgrid.com/v3/mail/send`

**Authentication:**
```
Authorization: Bearer ${SENDGRID_API_KEY}
```

**Configuration:**
- **API Key:** From environment variable (SENDGRID_API_KEY)
- **From Email:** From environment variable (SENDGRID_FROM_EMAIL)
- **Library:** @sendgrid/mail v8.1.5

**Request Flow:**

```
Express Backend → SendGrid API

POST /v3/mail/send

Request:
{
  "from": {
    "email": "noreply@company.com",
    "name": "Lamprell Resume Analyzer"
  },
  "personalizations": [{
    "to": [{
      "email": "recipient@example.com"
    }],
    "subject": "Resume Analysis Report - Job Title"
  }],
  "content": [{
    "type": "text/html",
    "value": "<html>...</html>"
  }]
}

Response (Success):
HTTP 202 Accepted
{
  // No body on success
}

Response (Error):
HTTP 4xx/5xx
{
  "errors": [{
    "message": "Error description",
    "field": "field_name",
    "help": "Additional guidance"
  }]
}
```

**Error Handling:**
- Invalid API key (401)
- Invalid email addresses (400)
- Rate limiting (429)
- SendGrid service errors (5xx)
- Network timeouts

**Graceful Degradation:**
- If SendGrid not configured (no API key), email feature disabled
- User notified if email service unavailable

---

### 3. PDF.js (Client-Side)

**CDN:** `https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/`

**Files Loaded:**
- pdf.min.js (main library)
- pdf.worker.min.js (worker thread)

**Usage Flow:**

```
Browser → PDF.js Library

1. Load PDF file as ArrayBuffer
   File.arrayBuffer() → ArrayBuffer data

2. Load PDF document
   pdfjsLib.getDocument(typedarray)
   → PDFDocumentProxy

3. For each page (max 100):
   pdf.getPage(pageNum)
   → PDFPageProxy

   page.getTextContent()
   → TextContent object

   Extract text items
   → Concatenate into single string

4. Return extracted text
```

**Configuration:**
- **Worker Path:** Set via pdfjsLib.GlobalWorkerOptions.workerSrc
- **Max Pages:** 100 pages per PDF
- **Timeout:** 20 seconds per PDF load

**Error Handling:**
- Invalid PDF format
- Corrupted PDF files
- Password-protected PDFs
- Load timeout
- Worker initialization failure

---

## Data Models

### 1. Database Schema

#### Users Table

**Table Name:** `users`

**Schema:**
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(50),
    last_login TIMESTAMP
);
```

**Constraints:**
- `id`: Auto-incrementing primary key
- `username`: Unique, not null, max 50 characters
- `password_hash`: bcrypt hash, not null, max 255 characters
- `is_admin`: Boolean flag for admin privileges
- `created_at`: Timestamp of user creation
- `created_by`: Username of creator (audit trail)
- `last_login`: Timestamp of most recent login

**Indexes:**
- Primary key on `id`
- Unique index on `username`

**Initial Data:**
- Default admin user created on startup:
  - Username: `hradmin`
  - Password: From `DEFAULT_ADMIN_PASSWORD` env var
  - is_admin: `true`

---

### 2. Request/Response Models

#### Job Requirements Object

**Source:** Response from `/api/extract-job-requirements`

**Structure:**
```json
{
  "technical_skills": [
    "JavaScript",
    "Node.js",
    "React",
    "SQL"
  ],
  "experience_requirements": [
    "5+ years of software development",
    "3+ years with React"
  ],
  "education_requirements": [
    "Bachelor's degree in Computer Science or related field"
  ],
  "soft_skills": [
    "Strong communication",
    "Team leadership"
  ],
  "industry_experience": [
    "Financial services",
    "E-commerce"
  ],
  "certifications": [
    "AWS Certified Solutions Architect"
  ],
  "additional_requirements": [
    "Remote work experience",
    "Agile methodology"
  ]
}
```

**Field Types:**
- All fields are arrays of strings
- Empty arrays if no requirements found
- Case-sensitive

---

#### Resume Data Object

**Source:** Response from `/api/extract-resume-data`

**Structure:**
```json
{
  "original_filename": "john_doe_resume.pdf",
  "name": "John Doe",
  "technical_skills": [
    "JavaScript",
    "Python",
    "Java",
    "SQL",
    "React",
    "Node.js"
  ],
  "experience_years": "5 years",
  "work_experience": [
    "Senior Software Engineer at Tech Corp (2020-2023): Led development of...",
    "Software Engineer at StartupXYZ (2018-2020): Built RESTful APIs..."
  ],
  "education": [
    "Bachelor of Science in Computer Science, University of California (2018)"
  ],
  "certifications": [
    "AWS Certified Developer",
    "Certified Scrum Master"
  ],
  "soft_skills": [
    "Leadership",
    "Communication",
    "Problem-solving"
  ],
  "industry_experience": [
    "Financial Technology",
    "E-commerce"
  ],
  "key_achievements": [
    "Reduced API response time by 40%",
    "Led team of 5 developers",
    "Implemented CI/CD pipeline"
  ],
  "tools_technologies": [
    "Git",
    "Docker",
    "Kubernetes",
    "Jenkins",
    "AWS"
  ]
}
```

**Field Types:**
- `original_filename`: String (filename with extension)
- `name`: String (candidate's full name)
- `experience_years`: String (formatted as "N years")
- All other fields: Arrays of strings

---

#### Analysis Result Object

**Source:** Response from `/api/analyze`

**Structure:**
```json
{
  "name": "john_doe_resume.pdf",
  "score": 92,
  "reasoning": "This candidate demonstrates an excellent match for the position with 5 years of relevant experience in JavaScript and Node.js development. Their background in financial technology aligns well with the industry requirements, and they possess the required AWS certification. Strong technical foundation with proven leadership experience.",
  "strengths": [
    "Extensive experience with required tech stack (JavaScript, Node.js, React)",
    "Relevant AWS certification",
    "Proven leadership experience managing development teams",
    "Strong background in financial services industry",
    "Demonstrated performance optimization skills"
  ],
  "weaknesses": [
    "Missing specific experience with GraphQL mentioned in requirements",
    "Limited frontend testing experience",
    "No mention of microservices architecture"
  ]
}
```

**Field Types:**
- `name`: String (resume filename)
- `score`: Number (0-100)
- `reasoning`: String (detailed explanation)
- `strengths`: Array of strings (typically 3-5 items)
- `weaknesses`: Array of strings (typically 2-4 items)

**Score Ranges:**
- 95-100: Perfect match
- 85-94: Excellent match
- 75-84: Very good match
- 65-74: Good match
- 55-64: Moderate match
- 45-54: Weak match
- <45: Poor match

**Sorting:**
- Results array sorted by score in descending order
- Highest scoring candidates appear first

---

#### User Object

**Source:** Response from `/api/login` and `/api/users`

**Structure:**
```json
{
  "id": 1,
  "username": "john.doe",
  "isAdmin": false,
  "created_at": "2023-10-15T14:30:00.000Z",
  "created_by": "hradmin",
  "last_login": "2023-12-10T09:15:00.000Z"
}
```

**Field Types:**
- `id`: Number (primary key)
- `username`: String
- `isAdmin`: Boolean
- `created_at`: ISO 8601 timestamp string
- `created_by`: String (username of creator, nullable)
- `last_login`: ISO 8601 timestamp string (nullable)

**Note:** `password_hash` never included in responses

---

### 3. Client-Side Storage Models

#### Session Storage

**Keys:**
```javascript
{
  "isLoggedIn": "true",      // String: "true" or "false"
  "username": "john.doe",    // String
  "isAdmin": "false",        // String: "true" or "false"
  "userId": "123"            // String (numeric ID)
}
```

**Lifecycle:**
- Created on successful login
- Cleared on logout
- Volatile (cleared when browser session ends)

---

#### Local Storage

**Keys:**
```javascript
{
  "additionalCriteria": "{\"criteria1\":\"value1\",\"criteria2\":\"value2\"}"
}
```

**Lifecycle:**
- Persisted across browser sessions
- Updated when user modifies additional criteria settings
- Retrieved on page load to restore settings

---

### 4. File Upload Models

#### File Validation Rules

**Accepted File Types:**
- PDF: `.pdf`
- Word: `.docx`, `.doc` (DOCX preferred)

**File Size Limits:**
- Max: 10 MB per file
- Enforced on both client and server

**Batch Limits:**
- Max resumes: 500 files
- Recommended: 200 files
- No limit on job description (single file only)

**File Object Structure (Client):**
```javascript
{
  name: "resume.pdf",
  size: 1048576,           // bytes
  type: "application/pdf",
  lastModified: 1701360000000
}
```

---

## Security & Rate Limiting

### 1. Rate Limiting Middleware

**Purpose:** Prevent API abuse and ensure fair resource allocation

**Configuration:**

```javascript
const activeRequests = new Map();      // Track concurrent requests by IP
const lastRequestTime = new Map();     // Track request timing by IP

// Limits
const MAX_CONCURRENT_REQUESTS = 3;     // Per IP
const MIN_REQUEST_INTERVAL = 1000;     // 1 second in milliseconds
const API_TIMEOUT = 60000;              // 60 seconds
```

**Flow:**

```
Incoming Request
      │
      ▼
┌─────────────────────────┐
│ Extract Client IP       │
│ (req.ip or x-real-ip)   │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────────────────┐
│ Check Concurrent Requests           │
│ activeRequests.get(ip) >= 3?        │
└───────────┬─────────────────────────┘
            │
     Yes    │    No
      ├─────┴─────┐
      ▼           ▼
┌──────────┐  ┌──────────────────────┐
│ 429 Too  │  │ Check Request Timing │
│ Many     │  │ Time since last < 1s?│
│ Requests │  └───────────┬──────────┘
└──────────┘              │
                   Yes    │    No
                    ├─────┴─────┐
                    ▼           ▼
              ┌──────────┐  ┌─────────────────┐
              │ 429 Too  │  │ Increment Count │
              │ Many     │  │ Update Timing   │
              │ Requests │  │ Proceed         │
              └──────────┘  └────────┬────────┘
                                     │
                                     ▼
                            ┌─────────────────┐
                            │ Execute Endpoint│
                            └────────┬────────┘
                                     │
                                     ▼
                            ┌─────────────────┐
                            │ On Response     │
                            │ Finish:         │
                            │ Decrement Count │
                            └─────────────────┘
```

**Response Headers:**
```
X-RateLimit-Limit: 3
X-RateLimit-Remaining: 2
X-RateLimit-Reset: <timestamp>
```

**Error Response (429):**
```json
{
  "error": "Too many requests. Please wait before retrying."
}
```

---

### 2. Authentication Security

#### Password Hashing

**Algorithm:** bcrypt with salt rounds = 10

**Flow:**
```
User Registration:
  plainTextPassword → bcrypt.hash(password, 10) → password_hash (stored)

User Login:
  plainTextPassword + stored_hash → bcrypt.compare() → Boolean (match/no match)
```

**bcrypt Properties:**
- One-way hashing (cannot reverse)
- Built-in salt generation
- Adaptive (computationally expensive to brute force)
- Industry standard

---

#### Password Complexity Requirements

**Regex Pattern:**
```regex
/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/
```

**Rules:**
- Minimum 8 characters
- At least 1 lowercase letter (a-z)
- At least 1 uppercase letter (A-Z)
- At least 1 digit (0-9)
- At least 1 special character (@$!%*?&)

**Validation:** Enforced on both client and server

**Error Message:**
```
Password must be at least 8 characters long and contain:
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (@$!%*?&)
```

---

#### Session Management

**Storage:** Browser sessionStorage (client-side)

**Session Data:**
```javascript
{
  isLoggedIn: "true",
  username: "john.doe",
  isAdmin: "false",
  userId: "123"
}
```

**Security Characteristics:**
- **Volatile:** Cleared when browser tab/window closes
- **Origin-scoped:** Only accessible from same origin
- **No server-side state:** Stateless authentication
- **No token expiry:** Session persists until browser close or manual logout

**Limitations:**
- No cross-tab synchronization
- Vulnerable to XSS (if malicious scripts injected)
- No server-side session invalidation

**Best Practice Improvements (Not Implemented):**
- Consider JWT with server-side validation
- Add session expiry/timeout
- Implement refresh token mechanism
- Use httpOnly cookies for sensitive data

---

### 3. API Key Validation

#### OpenRouter API Key

**Format Validation:**
```javascript
function isValidOpenRouterKey(key) {
  return key &&
         key.startsWith('sk-or-') &&
         key.length > 20;
}
```

**Enforcement:**
- Checked on startup
- Validated before each OpenRouter API call
- Error if invalid or missing

**Storage:** Environment variable (OPENROUTER_API_KEY)

---

#### SendGrid API Key

**Format:** Opaque string (no specific format required)

**Enforcement:**
- Optional (email feature disabled if not configured)
- Validated on first email send attempt
- Error from SendGrid API if invalid

**Storage:** Environment variable (SENDGRID_API_KEY)

---

### 4. HTTPS/TLS Security

#### Nginx SSL Configuration

**Certificate Type:** Self-signed (for local/development)

**Generation Script:** [nginx/generate-ssl-cert.sh]
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/key.pem \
  -out /etc/nginx/ssl/cert.pem \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

**Nginx Configuration:**
```nginx
listen 443 ssl;
ssl_certificate /etc/nginx/ssl/cert.pem;
ssl_certificate_key /etc/nginx/ssl/key.pem;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5;
```

**Security Headers:**
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options SAMEORIGIN always;
add_header X-Content-Type-Options nosniff always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

**HTTP → HTTPS Redirect:**
```nginx
server {
    listen 80;
    return 301 https://$host$request_uri;
}
```

---

### 5. Input Validation & Sanitization

#### File Upload Validation

**Client-Side:**
```javascript
// Extension check
const allowedExtensions = ['.pdf', '.docx', '.doc'];
const fileExtension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'));
if (!allowedExtensions.includes(fileExtension)) {
  throw new Error('Invalid file type');
}

// Size check
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
if (file.size > MAX_FILE_SIZE) {
  throw new Error('File too large');
}
```

**Server-Side:**
```javascript
// DOCX validation
if (!base64Data.startsWith('UEsDBBQ')) {  // ZIP signature (DOCX is ZIP)
  return res.status(400).json({
    error: 'Invalid DOCX file format'
  });
}

// Size validation
const buffer = Buffer.from(base64Data, 'base64');
if (buffer.length > MAX_FILE_SIZE) {
  return res.status(400).json({
    error: 'File too large'
  });
}
```

---

#### SQL Injection Prevention

**Method:** Parameterized queries via pg library

**Example:**
```javascript
// SAFE (parameterized)
const result = await pool.query(
  'SELECT * FROM users WHERE username = $1',
  [username]
);

// UNSAFE (avoid)
const result = await pool.query(
  `SELECT * FROM users WHERE username = '${username}'`
);
```

**All database queries use parameterized format ($1, $2, etc.)**

---

#### XSS Prevention

**Client-Side:**
```javascript
// Use textContent instead of innerHTML when possible
element.textContent = userInput;

// Sanitize HTML when necessary
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
```

**Server-Side:**
- Express automatically escapes JSON responses
- No user input directly rendered in HTML templates

---

## Error Handling Flow

### 1. Client-Side Error Handling

#### File Upload Errors

```
User uploads file
      │
      ▼
┌─────────────────────────┐
│ Validation Checks       │
│ 1. File extension       │
│ 2. File size            │
│ 3. File readability     │
└───────────┬─────────────┘
            │
     Error? │
      ├─────┴─────┐
      ▼           ▼
   Yes          No
      │           │
      ▼           ▼
┌──────────┐  ┌──────────┐
│ Display  │  │ Process  │
│ Error    │  │ File     │
│ Alert    │  │          │
└──────────┘  └──────────┘

Error Types:
- "Invalid file type. Please upload PDF or DOCX files only."
- "File too large. Maximum size is 10MB."
- "Unable to read file. Please try again."
```

---

#### API Request Errors

```
API Call (fetch)
      │
      ▼
┌─────────────────────────┐
│ try {                   │
│   const response =      │
│     await fetch()       │
│ }                       │
└───────────┬─────────────┘
            │
      Error?│
      ├─────┴─────┐
      ▼           ▼
   Yes          No
      │           │
      ▼           ▼
┌──────────────────┐  ┌──────────────┐
│ catch (error) {  │  │ Check        │
│   Handle network │  │ response.ok  │
│   errors         │  │              │
└──────────────────┘  └───────┬──────┘
                              │
                           No │ Yes
                        ┌─────┴─────┐
                        ▼           ▼
                  ┌──────────┐  ┌──────────┐
                  │ Parse    │  │ Parse    │
                  │ error    │  │ success  │
                  │ response │  │ response │
                  └────┬─────┘  └──────────┘
                       │
                       ▼
                  ┌──────────┐
                  │ Display  │
                  │ error to │
                  │ user     │
                  └──────────┘

Error Display Patterns:
- Toast notifications (auto-dismiss)
- Alert dialogs (user acknowledgement)
- Inline error messages (form fields)
- Progress bar errors (analysis pipeline)
```

---

### 2. Server-Side Error Handling

#### API Endpoint Error Pattern

```javascript
app.post('/api/endpoint', async (req, res) => {
  try {
    // 1. Input validation
    if (!req.body.requiredField) {
      return res.status(400).json({
        error: 'Missing required field'
      });
    }

    // 2. Business logic
    const result = await processData(req.body);

    // 3. Success response
    res.json({ success: true, data: result });

  } catch (error) {
    // 4. Error categorization
    console.error('Endpoint error:', error);

    if (error.code === 'TIMEOUT') {
      return res.status(504).json({
        error: 'Request timeout'
      });
    }

    if (error.code === 'ECONNREFUSED') {
      return res.status(503).json({
        error: 'External service unavailable'
      });
    }

    // 5. Generic error response
    res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
});
```

---

#### Database Error Handling

```
Database Query
      │
      ▼
┌─────────────────────────┐
│ try {                   │
│   await pool.query()    │
│ }                       │
└───────────┬─────────────┘
            │
      Error?│
      ├─────┴─────┐
      ▼           ▼
   Yes          No
      │           │
      ▼           ▼
┌──────────────────────────┐  ┌──────────┐
│ catch (error) {          │  │ Return   │
│   Check error.code       │  │ results  │
│ }                        │  │          │
└───────────┬──────────────┘  └──────────┘
            │
            ▼
Error Code Mapping:
┌────────────────┬────────────────────────┬──────────┐
│ PostgreSQL Code│ Meaning                │ HTTP     │
├────────────────┼────────────────────────┼──────────┤
│ 23505          │ Unique violation       │ 409      │
│ 23503          │ Foreign key violation  │ 400      │
│ 22P02          │ Invalid text format    │ 400      │
│ 53300          │ Too many connections   │ 503      │
│ 08000          │ Connection error       │ 503      │
│ (other)        │ Generic database error │ 500      │
└────────────────┴────────────────────────┴──────────┘
```

**Example Error Handler:**
```javascript
try {
  await pool.query('INSERT INTO users (username, ...) VALUES ($1, ...)', [username]);
} catch (error) {
  if (error.code === '23505') {  // Unique violation
    return res.status(409).json({
      error: 'Username already exists'
    });
  }
  throw error;  // Re-throw for generic handler
}
```

---

#### External API Error Handling

**OpenRouter API Errors:**

```
OpenRouter API Call
      │
      ▼
┌─────────────────────────────────┐
│ fetch(openRouterURL, {          │
│   method: 'POST',               │
│   headers: {...},               │
│   body: JSON.stringify(...)     │
│ })                              │
└───────────┬─────────────────────┘
            │
      Error?│
      ├─────┴─────┐
      ▼           ▼
   Yes          No
      │           │
      ▼           ▼
┌──────────────────────┐  ┌─────────────────┐
│ Network Error        │  │ Check HTTP      │
│ (timeout, ECONNRESET)│  │ status code     │
└───────────┬──────────┘  └────────┬────────┘
            │                      │
            ▼                      ▼
┌──────────────────────┐  ┌─────────────────┐
│ return res.status    │  │ 200: Success    │
│   (503).json({       │  │ 401: Invalid key│
│   error: "AI service"│  │ 429: Rate limit │
│   })                 │  │ 500: AI error   │
└──────────────────────┘  └────────┬────────┘
                                   │
                                   ▼
                          ┌─────────────────┐
                          │ Map to user-    │
                          │ friendly message│
                          └─────────────────┘

Error Message Examples:
- "AI service temporarily unavailable. Please try again."
- "Invalid API key configuration. Contact administrator."
- "Rate limit exceeded. Please wait before retrying."
- "AI processing error. The response was invalid."
```

**SendGrid API Errors:**

```
SendGrid API Call
      │
      ▼
┌─────────────────────────────────┐
│ sgMail.send({                   │
│   to: recipientEmail,           │
│   from: fromEmail,              │
│   subject: subject,             │
│   html: htmlContent             │
│ })                              │
└───────────┬─────────────────────┘
            │
      Error?│
      ├─────┴─────┐
      ▼           ▼
   Yes          No
      │           │
      ▼           ▼
┌──────────────────────────┐  ┌──────────┐
│ catch (error) {          │  │ 202:     │
│   Parse error.response   │  │ Accepted │
│   .body.errors[]         │  │          │
└───────────┬──────────────┘  └──────────┘
            │
            ▼
┌──────────────────────────────────────────┐
│ Error Details:                           │
│ - message: "Invalid email address"       │
│ - field: "to"                            │
│ - help: "Valid email format required"    │
└───────────┬──────────────────────────────┘
            │
            ▼
┌──────────────────────────┐
│ return res.status(400)   │
│   .json({                │
│   error: error.message   │
│ })                       │
└──────────────────────────┘
```

---

#### Word Document Processing Errors

**Categorized Error Handling:**

```
POST /api/extract-word-text
      │
      ▼
┌─────────────────────────┐
│ Validation              │
│ 1. File format (DOCX)   │
│ 2. File size (<10MB)    │
│ 3. Base64 decode        │
└───────────┬─────────────┘
            │
      Error?│
      ├─────┴─────┐
      ▼           ▼
   Yes          No
      │           │
      ▼           ▼
┌──────────┐  ┌──────────────────────┐
│ 400 Bad  │  │ Mammoth.js Process   │
│ Request  │  │ convertToHtml()      │
└──────────┘  └───────────┬──────────┘
                          │
                    Error?│
                    ├─────┴─────┐
                    ▼           ▼
                 Yes          No
                    │           │
                    ▼           ▼
            ┌────────────────────┐  ┌──────────┐
            │ Error Categorization│  │ Return   │
            │                    │  │ text     │
            └──────────┬─────────┘  └──────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│ Error Categories:                                   │
├─────────────────────────────────────────────────────┤
│ 1. Legacy DOC Format:                               │
│    - Error contains "OLE" or "Compound"             │
│    - Message: "Legacy DOC format not supported.     │
│      Please save as DOCX."                          │
│    - HTTP 400                                       │
├─────────────────────────────────────────────────────┤
│ 2. Corrupted File:                                  │
│    - Error contains "invalid" or "corrupt"          │
│    - Message: "File appears corrupted."             │
│    - HTTP 400                                       │
├─────────────────────────────────────────────────────┤
│ 3. Timeout:                                         │
│    - Processing exceeds 45 seconds                  │
│    - Message: "Processing timeout. File too large."│
│    - HTTP 504                                       │
├─────────────────────────────────────────────────────┤
│ 4. Generic Error:                                   │
│    - All other errors                               │
│    - Message: Error message + suggestion           │
│    - HTTP 500                                       │
└─────────────────────────────────────────────────────┘
```

**User-Friendly Error Messages:**
```
Legacy DOC:
"This appears to be a legacy .DOC file. Please open it in Microsoft Word
and save as .DOCX format, then try again."

Corrupted File:
"The file appears to be corrupted or in an unsupported format. Please
verify the file can be opened in Microsoft Word."

Timeout:
"The document is too large or complex to process. Try uploading a
smaller document or break it into sections."

Generic:
"Unable to extract text: [error details]. Please ensure the file is a
valid DOCX document."
```

---

### 3. Error Logging

**Console Logging Pattern:**
```javascript
console.error('[COMPONENT] Error type:', {
  message: error.message,
  stack: error.stack,
  context: relevantData
});
```

**Examples:**
```javascript
// Authentication error
console.error('[AUTH] Login failed:', {
  username: username,
  error: error.message,
  ip: req.ip
});

// Database error
console.error('[DB] Query failed:', {
  query: 'SELECT * FROM users',
  error: error.message,
  code: error.code
});

// External API error
console.error('[OPENROUTER] API call failed:', {
  endpoint: '/api/extract-job-requirements',
  status: response.status,
  error: await response.text()
});
```

**Production Considerations:**
- Logs written to stdout (captured by Docker)
- No sensitive data (passwords, API keys) in logs
- Consider structured logging library (e.g., Winston, Pino)
- Consider centralized logging (e.g., ELK, Datadog)

---

## Deployment Architecture

### Docker Compose Services

```yaml
services:
  app:                          # Node.js Backend
    container_name: hrtech_app
    build: .
    ports:
      - "3000:3000"
    depends_on:
      - db
    networks:
      - hrtech-network

  db:                           # PostgreSQL Database
    container_name: hrtech_db
    image: postgres:13-alpine
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - hrtech-network

  nginx:                        # Reverse Proxy
    container_name: hrtech_nginx
    build: ./nginx
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - app
    networks:
      - hrtech-network

networks:
  hrtech-network:
    driver: bridge

volumes:
  postgres_data:
```

### Container Communication

```
Internet (HTTPS) → Port 443
                      │
                      ▼
            ┌──────────────────┐
            │ hrtech_nginx     │
            │ (Nginx container)│
            └────────┬─────────┘
                     │
                     │ Internal network
                     │ (hrtech-network)
                     ▼
            ┌──────────────────┐
            │ hrtech_app       │
            │ (Node.js:3000)   │
            └────────┬─────────┘
                     │
                     │ Internal network
                     │ (hrtech-network)
                     ▼
            ┌──────────────────┐
            │ hrtech_db        │
            │ (PostgreSQL:5432)│
            └──────────────────┘
```

---

## Summary: Key Data Flows

### High-Traffic Paths

1. **Authentication Flow**: User login → bcrypt verification → session storage
2. **Resume Analysis Pipeline**: File upload → text extraction → AI parsing → scoring → results
3. **User Management**: Admin operations on user table

### Critical Integration Points

1. **OpenRouter API**: All AI processing (job parsing, resume parsing, analysis)
2. **SendGrid API**: Email delivery
3. **PostgreSQL**: User authentication and management

### Performance Bottlenecks

1. **Text Extraction**: ~3 seconds per file (sequential)
2. **AI API Calls**: ~2.5 seconds per resume (sequential, rate-limited)
3. **Batch Analysis**: Scales linearly with resume count

### Security Boundaries

1. **HTTPS/TLS**: All external communication encrypted
2. **Authentication**: bcrypt-hashed passwords, session-based auth
3. **Authorization**: Role-based (admin vs. regular user)
4. **Rate Limiting**: Per-IP request throttling
5. **Input Validation**: Client and server-side validation

---

## Document Maintenance

**Version History:**
- v1.0 (2025-12-10): Initial comprehensive data flow map

**Related Documentation:**
- [README.md](README.md) - Application overview and setup
- [QUICK-START.md](QUICK-START.md) - Quick deployment guide
- [DEPLOYMENT-HTTPS.md](DEPLOYMENT-HTTPS.md) - HTTPS configuration
- [FirewallWhitelist.md](FirewallWhitelist.md) - Network requirements

**Updates Needed When:**
- New API endpoints added
- External service integrations change
- Database schema modifications
- Authentication/authorization changes
- Rate limiting adjustments

---

**End of Data Flow Map**
