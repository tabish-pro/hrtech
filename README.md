
# 🎯 Lamprell Resume Analyzer

An AI-powered resume analysis and ranking tool designed to streamline the recruitment process by automatically evaluating candidate resumes against job descriptions using advanced language models.

![Resume Analyzer Banner](https://img.shields.io/badge/AI-Powered-blue?style=for-the-badge) ![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white) ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)

## 📋 Table of Contents

- [Features](#-features)
- [Technology Stack](#-technology-stack)
- [Prerequisites](#-prerequisites)
- [Installation & Setup](#-installation--setup)
- [Configuration](#-configuration)
- [Usage Guide](#-usage-guide)
- [User Management](#-user-management)
- [API Endpoints](#-api-endpoints)
- [File Processing](#-file-processing)
- [Deployment](#-deployment)
- [Security Features](#-security-features)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)

## ✨ Features

### Core Functionality
- **AI-Powered Analysis**: Leverages OpenRouter API with GPT-4o-mini for intelligent resume evaluation
- **Multi-Format Support**: Processes PDF, DOC, and DOCX files with robust extraction
- **Bulk Processing**: Handles up to 500 resumes simultaneously with rate limiting (200 recommended for optimal performance)
- **Smart Ranking**: Automatically ranks candidates based on job requirements match
- **Detailed Reporting**: Provides comprehensive analysis with strengths and weaknesses

### User Interface
- **Drag & Drop Upload**: Intuitive file upload with visual feedback
- **Real-Time Progress**: Live progress tracking with estimated completion times
- **Responsive Design**: Mobile-friendly interface with modern CSS animations
- **Interactive Results**: Sortable candidate rankings with detailed breakdowns

### Data Export & Sharing
- **PDF Reports**: Professional report generation with detailed candidate analysis
- **CSV Export**: Structured data export for further processing
- **Email Integration**: Direct report sharing via SendGrid API
- **Summary Tables**: Quick overview of all analyzed candidates

### Advanced Features
- **Custom Criteria**: Additional HR screening parameters for specialized requirements
- **Rate Limiting**: Built-in API protection against quota exhaustion
- **Error Handling**: Robust error recovery and user feedback
- **Session Management**: Secure user authentication and session handling

## 🛠 Technology Stack

### Backend
- **Node.js** - Server runtime environment
- **Express.js** - Web application framework
- **PostgreSQL** - User management and authentication database
- **bcrypt** - Password hashing and security

### AI & Document Processing
- **OpenRouter API** - AI language model integration
- **PDF.js** - PDF text extraction
- **Mammoth.js** - Word document processing
- **SendGrid** - Email delivery service

### Frontend
- **Vanilla JavaScript** - Client-side functionality
- **CSS3** - Modern styling with animations
- **HTML5** - Semantic markup structure
- **Font Awesome** - Icon library

## 📋 Prerequisites

Before setting up the application, ensure you have:

1. **Replit Account** - For hosting and deployment
2. **OpenRouter API Key** - For AI-powered analysis ([Get API Key](https://openrouter.ai/))
3. **SendGrid API Key** - For email functionality ([Get API Key](https://sendgrid.com/))
4. **PostgreSQL Database** - Available through Replit's database service

## 🚀 Installation & Setup

### 1. Fork the Template
1. Open the project in Replit
2. Fork or clone the repository
3. Wait for automatic dependency installation

### 2. Environment Configuration
Set up the following environment variables in Replit Secrets:

```bash
# Required - OpenRouter API for AI analysis
OPENROUTER_API_KEY=your_openrouter_api_key_here

# Required - Database connection
DATABASE_URL=your_postgresql_connection_string

# Optional - Email functionality
SENDGRID_API_KEY=your_sendgrid_api_key_here
```

### 3. Database Setup
The application automatically initializes the database with:
- User management tables
- Default admin account (`hradmin` / `hradmin@2025`)
- Proper indexing and constraints

### 4. Run the Application
```bash
npm install
node server.js
```

## ⚙️ Configuration

### API Keys

#### OpenRouter Setup
1. Visit [OpenRouter.ai](https://openrouter.ai/)
2. Create an account and generate an API key
3. Add the key to Replit Secrets as `OPENROUTER_API_KEY`
4. Supported models: GPT-4o-mini (default), Claude, and others

#### SendGrid Setup (Optional)
1. Create a [SendGrid account](https://sendgrid.com/)
2. Generate an API key with email sending permissions
3. Verify your sender email address
4. Add the key to Replit Secrets as `SENDGRID_API_KEY`

### Database Configuration
The PostgreSQL database is automatically configured with:
- User authentication table
- Session management
- Audit logging for user actions
- Automatic backup and recovery

## 📖 Usage Guide

### Getting Started

1. **Login**: Access the application using your credentials
   - Default admin: `hradmin` / `hradmin@2025`
   - Create additional users through the admin panel

2. **Upload Job Description**: 
   - Drag and drop or click to upload PDF/Word job description
   - Supports files up to 10MB

3. **Upload Resumes**:
   - Batch upload up to 500 resume files (200 recommended for best results)
   - Supported formats: PDF, DOC, DOCX
   - Individual file size limit: 10MB

4. **Configure Criteria** (Optional):
   - Click the settings button to add specific requirements
   - Technical skills prioritization
   - Experience level requirements
   - Education and certification preferences

5. **Analyze**:
   - Click "Analyze Resumes" to start AI processing
   - Monitor real-time progress with time estimates
   - Rate limiting ensures API quota management

6. **Review Results**:
   - View ranked candidate list with scores
   - Read detailed analysis for each candidate
   - Export reports in PDF or CSV format

### Advanced Features

#### Custom Screening Criteria
Enhance analysis accuracy by specifying:
- **Technical Skills**: Priority technologies and frameworks
- **Experience Level**: Years of experience and domain expertise
- **Soft Skills**: Leadership, communication, teamwork qualities
- **Education**: Degree requirements and certifications
- **Additional Requirements**: Industry-specific needs

#### Batch Processing Best Practices
- **File Preparation**: Ensure files are readable and not password-protected
- **Naming Convention**: Use descriptive filenames for easy identification
- **Size Management**: Keep batches under 200 files for optimal performance (500 max supported)
- **Quality Check**: Verify document text extraction before analysis

## 👥 User Management

### Admin Features (hradmin account)
- **User Creation**: Add up to 5 regular users
- **Password Management**: Reset and update user passwords
- **Account Monitoring**: View user activity and login history
- **User Deletion**: Remove inactive or unauthorized accounts

### Password Requirements
- Minimum 8 characters
- Must include uppercase and lowercase letters
- Must contain at least one number
- Must include special characters (@, $, !, %, *, ?, &)

### Security Features
- **Password Hashing**: bcrypt encryption with salt rounds
- **Session Management**: Secure session storage and timeout
- **Role-Based Access**: Admin vs. regular user permissions
- **Audit Logging**: Track user actions and system access

## 🔌 API Endpoints

### Authentication
```http
POST /api/login
Content-Type: application/json

{
  "username": "your_username",
  "password": "your_password"
}
```

### User Management (Admin Only)
```http
# Get all users
GET /api/users?adminUsername=hradmin

# Create new user
POST /api/users
{
  "username": "new_user",
  "password": "secure_password",
  "adminUsername": "hradmin"
}

# Update user password
PUT /api/users/:id/password
{
  "newPassword": "new_secure_password",
  "adminUsername": "hradmin"
}

# Delete user
DELETE /api/users/:id
{
  "adminUsername": "hradmin"
}
```

### Document Processing
```http
# Extract text from Word documents
POST /api/extract-word-text
{
  "fileData": "base64_encoded_file",
  "fileName": "document.docx"
}

# Extract job requirements
POST /api/extract-job-requirements
{
  "jobDescription": "job_description_text",
  "additionalCriteria": "optional_criteria"
}

# Extract resume data
POST /api/extract-resume-data
{
  "resumeText": "extracted_resume_text",
  "resumeName": "resume.pdf"
}

# Perform analysis
POST /api/analyze
{
  "jobRequirements": {...},
  "resumeDataList": [...]
}
```

### Email Integration
```http
POST /api/send-email
{
  "to": "hr@company.com",
  "subject": "Resume Analysis Report",
  "message": "Please find the analysis report below.",
  "reportData": [...]
}
```

## 📄 File Processing

### Supported Formats
- **PDF**: Text extraction using PDF.js library
- **DOC**: Legacy Word document processing via Mammoth
- **DOCX**: Modern Word document processing via Mammoth

### Processing Pipeline
1. **File Validation**: Size, format, and integrity checks
2. **Text Extraction**: Content parsing with error handling
3. **Rate Limiting**: 1-second delays between file processing
4. **Quality Assurance**: Minimum text length validation
5. **Error Recovery**: Graceful failure handling with user feedback

### Limitations
- Maximum 500 files per batch (200 recommended for best performance)
- 10MB per individual file
- Password-protected files not supported
- Image-only PDFs may have limited text extraction

## 🚀 Deployment

### Replit Deployment
1. **Prepare Environment**:
   - Ensure all secrets are configured
   - Test application functionality locally
   - Verify database connectivity

2. **Deploy Application**:
   - Click "Deploy" in the Replit interface
   - Choose "Autoscale Deployment" for high availability
   - Configure resource allocation (1 CPU, 1GB RAM recommended)
   - Set maximum instances based on expected traffic

3. **Production Configuration**:
   - Enable custom domain (optional)
   - Configure SSL certificates (automatic)
   - Set up monitoring and logging
   - Configure backup and recovery procedures

### Scaling Considerations
- **Traffic Management**: Autoscale handles up to 6,000 concurrent users
- **API Quotas**: Monitor OpenRouter usage and implement quotas
- **Database Performance**: PostgreSQL handles moderate concurrent loads
- **File Storage**: Temporary file processing, no persistent storage needed

### Environment Variables
```bash
# Production environment
NODE_ENV=production
PORT=3000

# Database (automatic in Replit)
DATABASE_URL=postgresql://...

# Required APIs
OPENROUTER_API_KEY=sk-or-...
SENDGRID_API_KEY=SG...

# Optional configurations
MAX_FILE_SIZE=10485760
MAX_BATCH_SIZE=50
API_TIMEOUT=30000
```

## 🔒 Security Features

### Data Protection
- **Password Encryption**: bcrypt hashing with salt rounds
- **Session Security**: HTTP-only cookies with secure flags
- **Input Validation**: Comprehensive sanitization and validation
- **File Scanning**: Malware and virus protection

### API Security
- **Rate Limiting**: Prevents API abuse and quota exhaustion
- **Request Throttling**: 1-second minimum intervals between requests
- **Timeout Protection**: 30-second maximum request duration
- **Error Masking**: Sensitive information protection in error messages

### Access Control
- **Role-Based Permissions**: Admin vs. user access levels
- **Session Management**: Automatic logout and session expiration
- **Audit Logging**: User action tracking and monitoring
- **IP Restrictions**: Optional IP-based access control

## 🐛 Troubleshooting

### Common Issues

#### API Key Problems
- **Symptom**: "OpenRouter API key is missing" error
- **Solution**: Verify `OPENROUTER_API_KEY` is set in Replit Secrets
- **Check**: Ensure key starts with "sk-or-" and is at least 20 characters

#### File Processing Errors
- **PDF Issues**: Ensure files are text-based, not image-only scans
- **Word Document Problems**: Verify files aren't password-protected
- **Size Limitations**: Check individual files are under 10MB

#### Database Connection
- **Symptom**: "Database connection failed"
- **Solution**: Verify `DATABASE_URL` is properly configured
- **Check**: Ensure PostgreSQL service is running in Replit

#### Rate Limiting
- **Symptom**: "Too many requests" errors
- **Solution**: Reduce batch size or increase processing delays
- **Monitor**: Check OpenRouter API usage and quotas

### Performance Optimization

#### Large Batch Processing
```javascript
// Recommended settings for 50+ resumes
const BATCH_SIZE = 25;
const PROCESSING_DELAY = 2000; // 2 seconds
const API_TIMEOUT = 45000; // 45 seconds
```

#### Memory Management
- Process files sequentially, not in parallel
- Clear temporary data after each file
- Monitor memory usage during large uploads

### Debugging Tools
- **Console Logging**: Detailed processing logs in browser console
- **Network Tab**: Monitor API requests and responses
- **Replit Logs**: Server-side error tracking and debugging

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Set up local environment with test API keys
4. Implement changes with proper testing
5. Submit pull request with detailed description

### Code Standards
- **ES6+ JavaScript**: Modern syntax and features
- **Async/Await**: Preferred over callbacks and promises
- **Error Handling**: Comprehensive try-catch blocks
- **Documentation**: Inline comments for complex logic

### Testing Guidelines
- Test with various file formats and sizes
- Verify user authentication and authorization
- Check API rate limiting and error handling
- Validate responsive design across devices

---

## 📞 Support

For issues, questions, or feature requests:
- Create an issue in the repository
- Check the troubleshooting section above
- Review the API documentation for integration help

---

**Made with ❤️ by the Lamprell Team | Powered by [Replit](https://replit.com)**

*This application uses AI for resume analysis. Results should be used as guidance alongside human judgment in recruitment decisions.*

----

# Firewall Whitelist — Lamprell Resume Analyzer

Notes:
- Allow HTTPS (TCP 443) to all listed hosts. Some OS package repos use HTTP/HTTPS; prefer HTTPS.
- Where apt repos are used, allow Ubuntu archive and security hosts for system updates.
- Container pulls (Docker) use Docker Hub registry endpoints (registry-1.docker.io / auth.docker.io).
- Node/npm package installs require access to npm registries and GitHub for some packages.
- AI/email API endpoints are required at runtime by the server (`OPENROUTER_API_KEY`, `SENDGRID_API_KEY`).

Core runtime / API services
- https://openrouter.ai
- https://openrouter.ai/api/v1
  - Notes: Used by server code via [`makeOpenRouterRequest()`](server.js) and [`queryAvailableModels()`](server.js). See [`OPENROUTER_API_KEY`](server.js).

- https://api.sendgrid.com
- https://sendgrid.com
  - Notes: Used for email sending (server expects `SENDGRID_API_KEY`) and SendGrid API calls (POST /v3/mail/send).

Package registries & build tooling
- https://registry.npmjs.org
- https://npmjs.com
- https://registry.yarnpkg.com (optional)
- https://nodejs.org
- https://deb.nodesource.com (if installing Node.js via NodeSource)
  - Notes: For `npm install`, Node runtime and many JS dependencies (e.g., `mammoth`, `openai` package).

Container images & registries
- https://registry-1.docker.io
- https://auth.docker.io
- https://hub.docker.com
- https://download.docker.com
- https://get.docker.com
  - Notes: Pulling official images (e.g., `postgres:13-alpine` from docker-compose), installing Docker Engine.

Git / source code hosting
- https://github.com
- https://api.github.com
- https://raw.githubusercontent.com
  - Notes: Cloning repo, fetching releases or raw files during builds.

Ubuntu / system package repos (required for apt / system updates)
- https://archive.ubuntu.com
- https://security.ubuntu.com
  - Notes: Base OS packages, apt updates, build deps when installing Docker/Node from apt.

Optional / common CDNs & tooling referenced in README/UI
- https://cdnjs.cloudflare.com (for Font Awesome / common libs if served from CDN)
- https://fonts.googleapis.com (if web fonts used)
  - Notes: May not be required if frontend bundles all assets, but whitelist if external CDNs are used.

Other useful endpoints (GPG/keys & misc)
- https://keyserver.ubuntu.com (if GPG key fetching is needed)
- https://packages.cloud.google.com (occasionally used by some build scripts; whitelist if required)

Database connectivity
- (Postgres runs locally or in Docker Compose; external DB URL if used:)
  - Allow the host specified by your `DATABASE_URL` (e.g., postgres server FQDN/IP + port 5432).
  - See [`DATABASE_URL`](server.js) and [docker-compose.yml](docker-compose.yml).

Ports
- Allow outbound TCP 443 (HTTPS) for all above hosts.
- If running PostgreSQL remotely, allow TCP 5432 to the DB host (only if external DB used).
- If exposing Docker daemon remotely (not recommended), allow TCP 2375/2376 as per your secure config.

Quick cross-check with workspace
- The server uses OpenRouter & SendGrid at runtime: see [`OPENROUTER_API_KEY`](server.js), [`SENDGRID_API_KEY`](server.js), and calls in [server.js](server.js).
- Docker images referenced in [docker-compose.yml](docker-compose.yml) will come from Docker Hub (registry-1.docker.io).
- Node packages are installed from npm registry: see [package.json](package.json).
- Frontend behavior and client-side uploads in [script.js](script.js) rely on the server APIs (no additional external endpoints required).
