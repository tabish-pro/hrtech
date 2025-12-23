class ResumeMatcherApp {
    constructor() {
        // Store CSRF token in memory
        this.csrfToken = null;

        // Check authentication first
        this.checkAuthentication();

        this.jobFile = null;
        this.resumeFiles = [];
        this.analysisResults = null;
        this.additionalCriteria = this.loadCriteria();

        // Fetch CSRF token before initializing
        this.fetchCsrfToken().then(() => {
            this.initializeEventListeners();
            this.initializeLogout();
        });
    }

    async fetchCsrfToken() {
        try {
            const response = await fetch('/api/csrf-token', {
                credentials: 'include'
            });
            const data = await response.json();
            this.csrfToken = data.csrfToken;
            console.log('CSRF token fetched successfully');
        } catch (error) {
            console.error('Failed to fetch CSRF token:', error);
        }
    }

    checkAuthentication() {
        const isLoggedIn = sessionStorage.getItem('isLoggedIn');
        const username = sessionStorage.getItem('username');

        if (!isLoggedIn || isLoggedIn !== 'true') {
            // Redirect to login page if not authenticated
            window.location.href = 'login.html';
            return;
        }

        // Add logout button and user info to header
        this.addUserInfo(username);
    }

    addUserInfo(username) {
        const headerContent = document.querySelector('.header-content');
        if (headerContent) {
            const isAdmin = sessionStorage.getItem('isAdmin') === 'true' || sessionStorage.getItem('isAdmin') === true;
            const isHrAdmin = username === 'hradmin';
            const showUserMgmt = isAdmin || isHrAdmin;

            console.log('User info debug:', { username, isAdmin, isHrAdmin, showUserMgmt });

            // Create user info element
            const userInfo = document.createElement('div');
            userInfo.className = 'user-info';
            userInfo.innerHTML = `
                <div class="user-details">
                    <span class="user-name"><i class="fas fa-user"></i> ${username}</span>
                    ${showUserMgmt ? '<button id="userMgmtBtn" class="user-mgmt-btn" title="User Management"><i class="fas fa-users-cog"></i> Manage Users</button>' : ''}
                    <button id="logoutBtn" class="logout-btn" title="Logout">
                        <i class="fas fa-sign-out-alt"></i>
                    </button>
                </div>
            `;

            // Insert before settings button
            const settingsBtn = document.getElementById('settingsBtn');
            headerContent.insertBefore(userInfo, settingsBtn);
        }
    }

    initializeLogout() {
        // Wait for DOM to be ready
        setTimeout(() => {
            const logoutBtn = document.getElementById('logoutBtn');
            if (logoutBtn) {
                logoutBtn.addEventListener('click', () => this.logout());
            }

            const userMgmtBtn = document.getElementById('userMgmtBtn');
            if (userMgmtBtn) {
                userMgmtBtn.addEventListener('click', () => this.showUserManagement());
            }
        }, 100);
    }

    logout() {
        if (confirm('Are you sure you want to logout?')) {
            sessionStorage.removeItem('isLoggedIn');
            sessionStorage.removeItem('username');
            sessionStorage.removeItem('isAdmin');
            sessionStorage.removeItem('userId');
            window.location.href = 'login.html';
        }
    }

    async showUserManagement() {
        const isAdmin = sessionStorage.getItem('isAdmin') === 'true' || sessionStorage.getItem('isAdmin') === true;
        const username = sessionStorage.getItem('username');
        const isHrAdmin = username === 'hradmin';

        if (!isAdmin && !isHrAdmin) {
            alert('Admin access required');
            return;
        }

        try {
            console.log('Fetching users for admin:', username);
            const response = await fetch('/api/users', {
                credentials: 'include' // Send JWT cookie with request
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error('API error response:', errorText);
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }

            const users = await response.json();
            console.log('Fetched users:', users);

            if (!Array.isArray(users)) {
                console.error('Invalid users data:', users);
                throw new Error('Invalid users data received');
            }

            this.displayUserManagementModal(users);
        } catch (error) {
            console.error('Failed to fetch users:', error);
            alert('Failed to load users: ' + error.message);
        }
    }

    displayUserManagementModal(users) {
        // Create modal HTML with three collapsible sections
        const modalHTML = `
            <div id="userMgmtModal" class="modal" style="display: flex;">
                <div class="modal-content user-mgmt-modal">
                    <div class="modal-header">
                        <h3><i class="fas fa-users-cog"></i> User Management</h3>
                        <span class="close" id="closeUserMgmt">&times;</span>
                    </div>
                    <div class="modal-body">
                        <!-- Create New User Section -->
                        <div class="collapsible-section">
                            <div class="section-header-collapsible" data-target="createUserSection">
                                <div class="section-title">
                                    <i class="fas fa-user-plus section-icon"></i>
                                    <h4>Create New User</h4>
                                </div>
                                <div class="section-meta">
                                    <small class="section-subtitle">Maximum 5 users allowed</small>
                                    <i class="fas fa-chevron-down toggle-icon"></i>
                                </div>
                            </div>
                            <div class="section-content" id="createUserSection">
                                <form id="createUserForm" class="create-user-form">
                                    <div class="form-row">
                                        <div class="form-group">
                                            <label for="newUsername">
                                                <i class="fas fa-user"></i>
                                                Username
                                            </label>
                                            <input type="text" id="newUsername" required maxlength="50" placeholder="Enter username">
                                        </div>
                                        <div class="form-group">
                                            <label for="newPassword">
                                                <i class="fas fa-lock"></i>
                                                Password
                                            </label>
                                            <input type="password" id="newPassword" required placeholder="Enter secure password">
                                            <small class="form-helper">Must be 8+ chars with uppercase, lowercase, number, and special character</small>
                                        </div>
                                    </div>
                                    <button type="submit" class="create-user-btn">
                                        <i class="fas fa-user-plus"></i> Create User
                                    </button>
                                </form>
                            </div>
                        </div>

                        <!-- Manage Existing Users Section -->
                        <div class="collapsible-section">
                            <div class="section-header-collapsible" data-target="existingUsersSection">
                                <div class="section-title">
                                    <i class="fas fa-users section-icon"></i>
                                    <h4>Manage Existing Users</h4>
                                </div>
                                <div class="section-meta">
                                    <small class="section-subtitle">${users.length} users registered</small>
                                    <i class="fas fa-chevron-down toggle-icon"></i>
                                </div>
                            </div>
                            <div class="section-content" id="existingUsersSection">
                                <div class="users-list" id="usersList">
                                    ${this.generateUsersListHTML(users)}
                                </div>
                            </div>
                        </div>

                        <!-- User Analytics Section -->
                        <div class="collapsible-section">
                            <div class="section-header-collapsible" data-target="analyticsSection">
                                <div class="section-title">
                                    <i class="fas fa-chart-bar section-icon"></i>
                                    <h4>User Analytics</h4>
                                </div>
                                <div class="section-meta">
                                    <small class="section-subtitle">Usage insights & metrics</small>
                                    <i class="fas fa-chevron-down toggle-icon"></i>
                                </div>
                            </div>
                            <div class="section-content" id="analyticsSection">
                                <div class="coming-soon">
                                    <div class="coming-soon-icon">
                                        <i class="fas fa-clock"></i>
                                    </div>
                                    <div class="coming-soon-content">
                                        <h5>Coming Soon</h5>
                                        <p>Detailed user analytics, login patterns, and usage statistics will be available here.</p>
                                        <div class="feature-preview">
                                            <div class="preview-item">
                                                <i class="fas fa-chart-line"></i>
                                                <span>Login Activity</span>
                                            </div>
                                            <div class="preview-item">
                                                <i class="fas fa-clock"></i>
                                                <span>Usage Patterns</span>
                                            </div>
                                            <div class="preview-item">
                                                <i class="fas fa-user-clock"></i>
                                                <span>Session Analytics</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Remove existing modal if any
        const existingModal = document.getElementById('userMgmtModal');
        if (existingModal) {
            existingModal.remove();
        }

        // Add modal to body
        document.body.insertAdjacentHTML('beforeend', modalHTML);

        // Add event listeners
        this.initializeUserManagementEvents();
        this.initializeCollapsibleSections();
    }

    generateUsersListHTML(users) {
        if (!users || !Array.isArray(users) || users.length === 0) {
            return '<div class="no-users-message">No users found</div>';
        }

        return users.map(user => {
            const username = user.username || 'Unknown User';
            const isAdmin = user.is_admin === true || user.is_admin === 'true';
            const createdAt = user.created_at ? new Date(user.created_at).toLocaleDateString() : 'Unknown';
            const lastLogin = user.last_login ? new Date(user.last_login).toLocaleDateString() : 'Never logged in';

            console.log('Generating HTML for user:', { username, isAdmin, createdAt, lastLogin });

            return `
                <div class="user-item" data-user-id="${user.id}">
                    <div class="user-info-section">
                        <div class="user-header">
                            <span class="username-display">${username}</span>
                            ${isAdmin ? '<span class="admin-badge">Admin</span>' : '<span class="user-badge">User</span>'}
                        </div>
                        <div class="user-metadata">
                            <small class="created-date">Created: ${createdAt}</small>
                            <small class="last-login-date">Last login: ${lastLogin}</small>
                        </div>
                    </div>
                    <div class="user-actions">
                        ${!isAdmin ? `
                            <button class="change-password-btn" data-user-id="${user.id}" title="Change password for ${username}">
                                <i class="fas fa-key"></i> Change Password
                            </button>
                            <button class="delete-user-btn" data-user-id="${user.id}" data-username="${username}" title="Delete user ${username}">
                                <i class="fas fa-trash"></i> Delete
                            </button>
                        ` : '<span class="admin-notice">Protected Admin Account</span>'}
                    </div>
                </div>
            `;
        }).join('');
    }

    initializeUserManagementEvents() {
        // Close modal
        document.getElementById('closeUserMgmt').addEventListener('click', () => {
            document.getElementById('userMgmtModal').remove();
        });

        // Create user form
        document.getElementById('createUserForm').addEventListener('submit', (e) => this.handleCreateUser(e));

        // Change password buttons
        document.querySelectorAll('.change-password-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.handleChangePassword(e.target.dataset.userId));
        });

        // Delete user buttons
        document.querySelectorAll('.delete-user-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.handleDeleteUser(e.target.dataset.userId, e.target.dataset.username));
        });
    }

    initializeCollapsibleSections() {
        // Add click handlers for collapsible sections
        document.querySelectorAll('.section-header-collapsible').forEach(header => {
            header.addEventListener('click', () => {
                const targetId = header.getAttribute('data-target');
                const content = document.getElementById(targetId);
                const toggleIcon = header.querySelector('.toggle-icon');
                const section = header.parentElement;

                // Toggle the section
                if (content.style.maxHeight && content.style.maxHeight !== '0px') {
                    // Collapse
                    content.style.maxHeight = '0px';
                    toggleIcon.style.transform = 'rotate(0deg)';
                    section.classList.remove('expanded');
                } else {
                    // Expand - use scrollHeight + extra padding for proper sizing
                    const actualHeight = content.scrollHeight + 50; // Add extra padding
                    content.style.maxHeight = actualHeight + 'px';
                    toggleIcon.style.transform = 'rotate(180deg)';
                    section.classList.add('expanded');
                    
                    // After animation, recalculate in case content changed
                    setTimeout(() => {
                        if (section.classList.contains('expanded')) {
                            const newHeight = content.scrollHeight + 50;
                            content.style.maxHeight = newHeight + 'px';
                        }
                    }, 400);
                }
            });
        });

        // Set initial state - all sections collapsed by default
        setTimeout(() => {
            const allSections = ['createUserSection', 'existingUsersSection', 'analyticsSection'];
            allSections.forEach(sectionId => {
                const content = document.getElementById(sectionId);
                const header = document.querySelector(`[data-target="${sectionId}"]`);
                const toggleIcon = header.querySelector('.toggle-icon');
                const section = header.parentElement;
                
                if (content && header) {
                    // Set collapsed state
                    content.style.maxHeight = '0px';
                    toggleIcon.style.transform = 'rotate(0deg)';
                    section.classList.remove('expanded');
                }
            });
        }, 100);
    }

    async handleCreateUser(e) {
        e.preventDefault();

        const username = document.getElementById('newUsername').value.trim();
        const password = document.getElementById('newPassword').value;
        const submitBtn = e.target.querySelector('button[type="submit"]');

        if (!username || !password) {
            alert('Please fill in all fields');
            return;
        }

        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating...';
        submitBtn.disabled = true;

        try {
            const response = await fetch('/api/users', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-csrf-token': this.csrfToken // Add CSRF token
                },
                credentials: 'include', // Send JWT cookie
                body: JSON.stringify({
                    username,
                    password
                })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Failed to create user');
            }

            alert(`User "${username}" created successfully!`);

            // Clear form
            document.getElementById('newUsername').value = '';
            document.getElementById('newPassword').value = '';

            // Close current modal and reopen with refreshed data
            document.getElementById('userMgmtModal').remove();

            // Small delay to ensure modal is removed before showing new one
            setTimeout(() => {
                this.showUserManagement();
            }, 100);

        } catch (error) {
            console.error('Create user error:', error);
            alert('Failed to create user: ' + error.message);
        } finally {
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        }
    }

    async handleChangePassword(userId) {
        const newPassword = prompt('Enter new password:\n(Must be 8+ characters with uppercase, lowercase, number, and special character)');

        if (!newPassword) return;

        try {
            const response = await fetch(`/api/users/${userId}/password`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'x-csrf-token': this.csrfToken // Add CSRF token
                },
                credentials: 'include', // Send JWT cookie
                body: JSON.stringify({
                    newPassword
                })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Failed to change password');
            }

            alert('Password changed successfully!');

        } catch (error) {
            console.error('Change password error:', error);
            alert('Failed to change password: ' + error.message);
        }
    }

    async handleDeleteUser(userId, username) {
        if (!confirm(`Are you sure you want to delete user "${username}"? This action cannot be undone.`)) {
            return;
        }

        try {
            const response = await fetch(`/api/users/${userId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'x-csrf-token': this.csrfToken // Add CSRF token
                },
                credentials: 'include' // Send JWT cookie
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Failed to delete user');
            }

            alert(`User "${username}" deleted successfully!`);

            // Close current modal and reopen with refreshed data
            document.getElementById('userMgmtModal').remove();

            // Small delay to ensure modal is removed before showing new one
            setTimeout(() => {
                this.showUserManagement();
            }, 100);

        } catch (error) {
            console.error('Delete user error:', error);
            alert('Failed to delete user: ' + error.message);
        }
    }

    initializeEventListeners() {
        // Job file upload
        const jobUploadArea = document.getElementById('jobUploadArea');
        const jobFileInput = document.getElementById('jobFile');

        jobUploadArea.addEventListener('click', () => jobFileInput.click());
        jobUploadArea.addEventListener('dragover', this.handleDragOver.bind(this));
        jobUploadArea.addEventListener('dragleave', this.handleDragLeave.bind(this));
        jobUploadArea.addEventListener('drop', (e) => this.handleJobDrop(e));
        jobFileInput.addEventListener('change', (e) => this.handleJobFileSelect(e));

        // Resume files upload
        const resumeUploadArea = document.getElementById('resumeUploadArea');
        const resumeFileInput = document.getElementById('resumeFiles');

        resumeUploadArea.addEventListener('click', () => resumeFileInput.click());
        resumeUploadArea.addEventListener('dragover', this.handleDragOver.bind(this));
        resumeUploadArea.addEventListener('dragleave', this.handleDragLeave.bind(this));
        resumeUploadArea.addEventListener('drop', (e) => this.handleResumeDrop(e));
        resumeFileInput.addEventListener('change', (e) => this.handleResumeFileSelect(e));

        // Analysis button
        document.getElementById('analyzeBtn').addEventListener('click', () => this.analyzeResumes());

        // Delete job file button
        document.getElementById('deleteJobBtn').addEventListener('click', () => this.deleteJobFile());

        // Report actions
        document.getElementById('downloadReportBtn').addEventListener('click', () => this.downloadReport());
        document.getElementById('emailReportBtn').addEventListener('click', () => this.showEmailModal());
        document.getElementById('downloadCsvBtn').addEventListener('click', () => this.downloadCsv());

        // Email modal
        document.getElementById('sendEmailBtn').addEventListener('click', () => this.sendEmailReport());
        document.getElementById('cancelEmailBtn').addEventListener('click', () => this.hideEmailModal());
        document.querySelector('.close').addEventListener('click', () => this.hideEmailModal());

        // Settings panel
        document.getElementById('settingsBtn').addEventListener('click', () => this.showSettings());
        document.getElementById('closeSettingsBtn').addEventListener('click', () => this.hideSettings());
        document.querySelector('.settings-overlay').addEventListener('click', () => this.hideSettings());
        document.getElementById('saveCriteriaBtn').addEventListener('click', () => this.saveCriteria());
        document.getElementById('clearCriteriaBtn').addEventListener('click', () => this.clearCriteria());
    }

    handleDragOver(e) {
        e.preventDefault();
        e.currentTarget.classList.add('dragover');
    }

    handleDragLeave(e) {
        e.preventDefault();
        e.currentTarget.classList.remove('dragover');
    }

    handleJobDrop(e) {
        e.preventDefault();
        e.currentTarget.classList.remove('dragover');
        const files = Array.from(e.dataTransfer.files);
        
        if (files.length > 0) {
            const file = files[0];
            const fileExtension = file.name.toLowerCase().split('.').pop();
            
            if (fileExtension === 'pdf' || fileExtension === 'docx') {
                this.setJobFile(file);
            } else {
                alert(`Unsupported file format: .${fileExtension}\n\nOnly PDF and DOCX files are supported. Please convert your file to one of these formats and try again.`);
            }
        }
    }

    handleResumeDrop(e) {
        e.preventDefault();
        e.currentTarget.classList.remove('dragover');
        const files = Array.from(e.dataTransfer.files);
        
        // Filter and validate files by extension
        const validFiles = [];
        const invalidFiles = [];
        
        files.forEach(file => {
            const fileExtension = file.name.toLowerCase().split('.').pop();
            if (fileExtension === 'pdf' || fileExtension === 'docx') {
                validFiles.push(file);
            } else {
                invalidFiles.push(file.name);
            }
        });
        
        if (invalidFiles.length > 0) {
            alert(`Unsupported file formats detected:\n${invalidFiles.join('\n')}\n\nOnly PDF and DOCX files are supported. Please convert these files and try again.`);
        }
        
        if (validFiles.length > 0) {
            this.validateAndSetResumeFiles(validFiles);
        }
    }

    handleJobFileSelect(e) {
        const file = e.target.files[0];
        if (file) {
            const fileExtension = file.name.toLowerCase().split('.').pop();
            
            if (fileExtension === 'pdf' || fileExtension === 'docx') {
                this.setJobFile(file);
            } else {
                alert(`Unsupported file format: .${fileExtension}\n\nOnly PDF and DOCX files are supported. Please select a PDF or DOCX file.`);
                e.target.value = ''; // Clear the input
            }
        }
    }

    handleResumeFileSelect(e) {
        const files = Array.from(e.target.files);
        
        // Filter and validate files by extension
        const validFiles = [];
        const invalidFiles = [];
        
        files.forEach(file => {
            const fileExtension = file.name.toLowerCase().split('.').pop();
            if (fileExtension === 'pdf' || fileExtension === 'docx') {
                validFiles.push(file);
            } else {
                invalidFiles.push(file.name);
            }
        });
        
        if (invalidFiles.length > 0) {
            alert(`Unsupported file formats detected:\n${invalidFiles.join('\n')}\n\nOnly PDF and DOCX files are supported. Please select only PDF or DOCX files.`);
            e.target.value = ''; // Clear the input
            return;
        }
        
        this.validateAndSetResumeFiles(validFiles);
    }

    setJobFile(file) {
        this.jobFile = file;
        this.updateJobFileDisplay();
        this.updateAnalyzeButton();
    }

    validateAndSetResumeFiles(files) {
        if (files.length > 500) {
            alert('Maximum 500 resume files allowed for analysis. Please select up to 500 files only.');

            // Clear the file input
            document.getElementById('resumeFiles').value = '';
            return;
        }

        this.setResumeFiles(files);
    }

    setResumeFiles(files) {
        this.resumeFiles = files;
        this.updateResumeFilesDisplay();
        this.updateAnalyzeButton();
    }

    updateJobFileDisplay() {
        const infoDiv = document.getElementById('jobFileInfo');
        if (this.jobFile) {
            const fileExtension = this.jobFile.name.toLowerCase().split('.').pop();
            const icon = fileExtension === 'pdf' ? 'fa-file-pdf' : 'fa-file-word';
            infoDiv.innerHTML = `
                <div class="file-item">
                    <i class="fas ${icon}"></i>
                    <span>${this.jobFile.name}</span>
                    <small>(${this.formatFileSize(this.jobFile.size)})</small>
                </div>
                <button id="deleteJobBtn" class="delete-file-btn" title="Remove job description">
                    <i class="fas fa-times"></i>
                </button>
            `;
            infoDiv.style.display = 'block';

            // Re-attach event listener after updating innerHTML
            document.getElementById('deleteJobBtn').addEventListener('click', () => this.deleteJobFile());
        } else {
            infoDiv.style.display = 'none';
        }
    }

    updateResumeFilesDisplay() {
        const infoDiv = document.getElementById('resumeFileInfo');
        if (this.resumeFiles.length > 0) {
            const fileItems = this.resumeFiles.map(file => {
                const fileExtension = file.name.toLowerCase().split('.').pop();
                const icon = fileExtension === 'pdf' ? 'fa-file-pdf' : 'fa-file-word';
                return `
                    <div class="file-item">
                        <i class="fas ${icon}"></i>
                        <span>${file.name}</span>
                        <small>(${this.formatFileSize(file.size)})</small>
                    </div>
                `;
            }).join('');
            infoDiv.innerHTML = fileItems;
            infoDiv.style.display = 'block';
        } else {
            infoDiv.style.display = 'none';
        }
    }

    updateAnalyzeButton() {
        const btn = document.getElementById('analyzeBtn');
        btn.disabled = !this.jobFile || this.resumeFiles.length === 0;
    }

    deleteJobFile() {
        this.jobFile = null;
        document.getElementById('jobFile').value = '';
        this.updateJobFileDisplay();
        this.updateAnalyzeButton();
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async analyzeResumes() {
        const analyzeBtn = document.getElementById('analyzeBtn');
        const originalText = analyzeBtn.innerHTML;

        try {
            // Final validation check before starting analysis
            if (!this.validateFileTypesBeforeAnalysis()) {
                return;
            }

            // Disable button and show progress
            analyzeBtn.disabled = true;
            analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';

            // Hide loading and results first, then show progress bar
            this.hideLoading();
            document.getElementById('resultsSection').style.display = 'none';
            this.showProgressBar(); // Show progress bar immediately

            const totalSteps = this.resumeFiles.length + 3; // +3 for job extraction, resume processing, and final analysis
            let currentStep = 0;

            // Update progress for job description extraction
            this.updateProgress(currentStep++, totalSteps, "Extracting job requirements...");
            const jobText = await this.extractTextFromPDF(this.jobFile);

            // Extract text from all resumes with optimized processing
            const resumeData = [];
            const RATE_LIMIT_DELAY = 300; // Reduced to 300ms for better performance
            const BATCH_SIZE = 5; // Process in small batches

            for (let i = 0; i < this.resumeFiles.length; i += BATCH_SIZE) {
                const batch = this.resumeFiles.slice(i, i + BATCH_SIZE);
                const batchPromises = batch.map(async (file, batchIndex) => {
                    const fileIndex = i + batchIndex;
                    this.updateProgress(currentStep + fileIndex, totalSteps, `Processing ${file.name}... (${fileIndex + 1}/${this.resumeFiles.length})`);

                    try {
                        const resumeText = await this.extractTextFromPDF(file);
                        return {
                            name: file.name,
                            text: resumeText
                        };
                    } catch (fileError) {
                        console.error(`Failed to process ${file.name}:`, fileError);
                        return {
                            name: file.name,
                            text: `ERROR: Could not extract text from ${file.name}. Reason: ${fileError.message}`,
                            hasError: true
                        };
                    }
                });

                // Process batch concurrently
                const batchResults = await Promise.all(batchPromises);
                resumeData.push(...batchResults);
                currentStep += batch.length;

                // Brief delay between batches to prevent overwhelming the system
                if (i + BATCH_SIZE < this.resumeFiles.length) {
                    await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_DELAY));
                }
            }

            // Final analysis step
            this.updateProgress(currentStep++, totalSteps, "Performing AI analysis...");
            const results = await this.analyzeWithOpenAI(jobText, resumeData);

            // Complete progress
            this.updateProgress(totalSteps, totalSteps, "Analysis complete!");

            // Wait a moment before showing results
            await new Promise(resolve => setTimeout(resolve, 1000));

            this.analysisResults = results;
            this.displayResults(results);

        } catch (error) {
            console.error('Analysis failed:', error);
            console.error('Error details:', error.message);

            if (error.message.includes('API key') || error.message.includes('OpenRouter') || error.message.includes('key')) {
                alert(`Analysis failed due to API configuration issues: ${error.message}`);
            } else if (error.message.includes('network') || error.message.includes('fetch')) {
                alert(`Network error during analysis: ${error.message}`);
            } else {
                alert(`Analysis failed: ${error.message || 'Unknown error occurred'}`);
            }
        } finally {
            // Restore button state
            analyzeBtn.disabled = false;
            analyzeBtn.innerHTML = originalText;

            this.hideLoading();
            setTimeout(() => {
                this.hideProgressBar();
            }, 2000); // Keep progress visible for 2 seconds after completion
        }
    }

    async extractTextFromPDF(file) {
        try {
            console.log(`Extracting text from: ${file.name}`);

            // File size validation (10MB limit)
            const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
            if (file.size > MAX_FILE_SIZE) {
                throw new Error(`File ${file.name} is too large (${this.formatFileSize(file.size)}). Maximum size allowed is 10MB.`);
            }

            // Check if it's a Word document
            const fileExtension = file.name.toLowerCase().split('.').pop();
            const isWordDocument = fileExtension === 'doc' || fileExtension === 'docx';

            if (isWordDocument) {
                return await this.extractTextFromWordDocument(file);
            } else {
                return await this.extractTextFromPDFDocument(file);
            }

        } catch (error) {
            console.error(`Text extraction failed for ${file.name}:`, error);
            console.error('Full error details:', error);

            // More specific error message based on file type and error
            const fileExtension = file.name.toLowerCase().split('.').pop();
            const isWordDocument = fileExtension === 'doc' || fileExtension === 'docx';

            if (isWordDocument) {
                if (error.message.includes('base64') || error.message.includes('conversion')) {
                    throw new Error(`Failed to process Word document ${file.name}: File conversion error. ${error.message}`);
                } else if (error.message.includes('Mammoth') || error.message.includes('format')) {
                    throw new Error(`Failed to extract text from Word document ${file.name}: Document format issue. ${error.message}`);
                } else {
                    throw new Error(`Failed to extract text from Word document ${file.name}: ${error.message}`);
                }
            } else {
                if (error.message.includes('timeout')) {
                    throw new Error(`PDF processing timed out for ${file.name}. The file may be too complex or large.`);
                } else if (error.message.includes('password') || error.message.includes('encrypted')) {
                    throw new Error(`PDF ${file.name} appears to be password-protected or encrypted.`);
                } else {
                    throw new Error(`Failed to extract text from PDF ${file.name}: ${error.message}`);
                }
            }
        }
    }

    async extractTextFromWordDocument(file) {
        try {
            console.log(`Extracting text from Word document: ${file.name}`);
            console.log(`File size: ${file.size} bytes`);
            console.log(`File type: ${file.type}`);

            // Validate file extension more strictly
            const fileExtension = file.name.toLowerCase().split('.').pop();
            const validExtensions = ['doc', 'docx'];
            if (!validExtensions.includes(fileExtension)) {
                throw new Error(`Unsupported file extension: .${fileExtension}. Only .doc and .docx files are supported.`);
            }

            // Validate MIME type if available
            if (file.type && !file.type.includes('word') && !file.type.includes('document') && !file.type.includes('officedocument')) {
                console.warn(`Unexpected MIME type for Word document: ${file.type}`);
            }

            // Convert file to base64 with better error handling and memory management
            let arrayBuffer, base64String;
            try {
                arrayBuffer = await file.arrayBuffer();
                console.log(`ArrayBuffer length: ${arrayBuffer.byteLength}`);

                // For large files, use a more memory-efficient approach
                if (arrayBuffer.byteLength > 5 * 1024 * 1024) { // 5MB threshold
                    console.log('Large file detected, using chunked base64 conversion...');
                    const uint8Array = new Uint8Array(arrayBuffer);
                    const chunkSize = 4096; // Smaller chunks for large files
                    let binary = '';

                    for (let i = 0; i < uint8Array.length; i += chunkSize) {
                        const chunk = uint8Array.slice(i, i + chunkSize);
                        binary += String.fromCharCode.apply(null, chunk);

                        // Allow other operations to run to prevent blocking
                        if (i % (chunkSize * 100) === 0) {
                            await new Promise(resolve => setTimeout(resolve, 1));
                        }
                    }

                    base64String = btoa(binary);
                } else {
                    // Standard conversion for smaller files
                    const uint8Array = new Uint8Array(arrayBuffer);
                    const chunkSize = 8192;
                    let binary = '';

                    for (let i = 0; i < uint8Array.length; i += chunkSize) {
                        const chunk = uint8Array.slice(i, i + chunkSize);
                        binary += String.fromCharCode.apply(null, chunk);
                    }

                    base64String = btoa(binary);
                }

                console.log(`Base64 string length: ${base64String.length}`);

            } catch (conversionError) {
                console.error('File conversion error:', conversionError);
                throw new Error(`Failed to convert file to base64: ${conversionError.message}`);
            }

            // Call the server-side Word extraction API
            console.log('Sending request to server for Word text extraction...');
            const response = await fetch('/api/extract-word-text', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    fileData: base64String,
                    fileName: file.name
                })
            });

            console.log(`Server response status: ${response.status}`);

            if (!response.ok) {
                const errorText = await response.text();
                console.error('Server error response:', errorText);

                let errorData;
                try {
                    errorData = JSON.parse(errorText);
                } catch (parseError) {
                    console.error('Could not parse error response as JSON');
                    errorData = { details: `Server error: ${response.status} - ${errorText}` };
                }

                throw new Error(errorData.details || `Server error: ${response.status}`);
            }

            const result = await response.json();
            console.log(`Server extraction result:`, result);
            console.log(`Extracted ${result.text.length} characters from Word document: ${file.name}`);
            console.log(`Preview: ${result.text.substring(0, 200)}...`);

            if (!result.text || result.text.trim().length < 10) {
                console.error('Very short text extracted from Word document:', result);
                throw new Error(`Minimal text extracted from Word document. Extracted length: ${result.text ? result.text.length : 0}`);
            }

            return result.text;

        } catch (error) {
            console.error(`Word document extraction failed for ${file.name}:`, error);
            console.error('Error details:', error.message);
            throw error;
        }
    }

    async extractTextFromPDFDocument(file) {
        let arrayBuffer = null;
        let pdf = null;
        
        try {
            console.log(`Extracting text from PDF document: ${file.name}`);

            // Set PDF.js worker
            pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';

            arrayBuffer = await file.arrayBuffer();

            // Add timeout for PDF loading
            const loadingPromise = pdfjsLib.getDocument(arrayBuffer).promise;
            const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('PDF loading timed out after 20 seconds')), 20000)
            );

            pdf = await Promise.race([loadingPromise, timeoutPromise]);

            const textChunks = [];
            const maxPages = Math.min(pdf.numPages, 100); // Limit to 100 pages for memory efficiency

            // Extract text from each page with memory management
            for (let pageNum = 1; pageNum <= maxPages; pageNum++) {
                const page = await pdf.getPage(pageNum);
                const textContent = await page.getTextContent();

                // Process text items in chunks to avoid large string concatenations
                const pageTextItems = textContent.items.map(item => item.str).filter(str => str.trim());
                
                if (pageTextItems.length > 0) {
                    const pageText = pageTextItems.join(' ').replace(/\s+/g, ' ').trim();
                    if (pageText) {
                        textChunks.push(pageText);
                    }
                }

                // Clean up page reference
                page.cleanup();
                
                // Allow garbage collection every 10 pages
                if (pageNum % 10 === 0 && global.gc) {
                    global.gc();
                }
            }

            // Efficiently join text chunks
            let fullText = textChunks.join('\n\n').trim();
            
            // Clear chunks array for GC
            textChunks.length = 0;

            console.log(`Extracted ${fullText.length} characters from PDF: ${file.name}`);

            if (!fullText || fullText.length < 50) {
                console.warn(`Very short text extracted from ${file.name}, might be an issue`);
                throw new Error(`Limited text could be extracted from ${file.name}. File may be image-based or encrypted.`);
            }

            return fullText;

        } catch (error) {
            console.error(`PDF extraction failed for ${file.name}:`, error);
            throw error;
        } finally {
            // Cleanup resources
            if (pdf) {
                pdf.destroy();
            }
            arrayBuffer = null;
        }
    }

    async analyzeWithOpenAI(jobDescription, resumeData) {
        try {
            // Input validation
            if (!jobDescription || jobDescription.trim().length < 50) {
                throw new Error('Job description must be at least 50 characters long.');
            }

            if (!resumeData || !Array.isArray(resumeData) || resumeData.length === 0) {
                throw new Error('At least one resume is required for analysis.');
            }

            // Check for very short resume texts that might indicate extraction issues
            const problematicResumes = resumeData.filter(resume => 
                !resume.text || resume.text.trim().length < 100
            );

            if (problematicResumes.length > 0) {
                console.warn('Some resumes have very short text, possible extraction issues:', 
                    problematicResumes.map(r => r.name));
            }

            // Step 1: Extract job requirements
            console.log('Extracting job requirements...');
            const criteriaPrompt = this.buildCriteriaPrompt();

            let jobRequirementsResponse;
            try {
                jobRequirementsResponse = await fetch('/api/extract-job-requirements', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        jobDescription,
                        additionalCriteria: criteriaPrompt
                    })
                });
            } catch (networkError) {
                throw new Error(`Network error during job requirements extraction: ${networkError.message}`);
            }

            if (!jobRequirementsResponse.ok) {
                const errorText = await jobRequirementsResponse.text();
                console.error('Job requirements API error response:', errorText);
                let errorData = {};
                try {
                    errorData = JSON.parse(errorText);
                } catch (parseError) {
                    console.error('Could not parse error response as JSON');
                }
                throw new Error(errorData.details || errorData.error || `Job requirements extraction failed with status: ${jobRequirementsResponse.status} - ${errorText}`);
            }

            const jobRequirements = await jobRequirementsResponse.json();

            // Validate job requirements structure
            if (!jobRequirements || typeof jobRequirements !== 'object') {
                throw new Error('Invalid job requirements format received from API.');
            }

            console.log('Job requirements extracted:', jobRequirements);

            // Step 2: Extract resume data for each resume with rate limiting
            console.log('Extracting resume data...');
            const resumeDataList = [];
            const API_RATE_LIMIT_DELAY = 1500; // 1.5 seconds between API calls
            let successfulExtractions = 0;
            let failedExtractions = 0;

            for (let i = 0; i < resumeData.length; i++) {
                const resume = resumeData[i];
                console.log(`Processing resume: ${resume.name} (${i + 1}/${resumeData.length})`);

                // Skip resumes that had extraction errors
                if (resume.hasError) {
                    console.log(`Skipping ${resume.name} due to previous extraction error`);
                    failedExtractions++;
                    continue;
                }

                console.log(`Resume text preview: ${resume.text.substring(0, 200)}...`);

                let retryCount = 0;
                const maxRetries = 2;
                let extractedResumeData = null;

                while (retryCount <= maxRetries && !extractedResumeData) {
                    try {
                        if (retryCount > 0) {
                            console.log(`Retry attempt ${retryCount} for ${resume.name}`);
                            // Extra delay for retries
                            await new Promise(resolve => setTimeout(resolve, 2000));
                        }

                        const resumeExtractionResponse = await fetch('/api/extract-resume-data', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                resumeText: resume.text,
                                resumeName: resume.name
                            }),
                            signal: AbortSignal.timeout(30000) // 30 second timeout
                        });

                        if (!resumeExtractionResponse.ok) {
                            const errorText = await resumeExtractionResponse.text();
                            throw new Error(`API error ${resumeExtractionResponse.status}: ${errorText}`);
                        }

                        extractedResumeData = await resumeExtractionResponse.json();
                        console.log(`Extracted data for ${resume.name}:`, extractedResumeData);
                        resumeDataList.push(extractedResumeData);
                        successfulExtractions++;

                        // Rate limiting delay between successful API calls
                        if (i < resumeData.length - 1) {
                            await new Promise(resolve => setTimeout(resolve, API_RATE_LIMIT_DELAY));
                        }

                    } catch (error) {
                        console.error(`Resume extraction attempt ${retryCount + 1} failed for ${resume.name}:`, error);
                        retryCount++;

                        if (retryCount > maxRetries) {
                            console.error(`All retry attempts failed for ${resume.name}, skipping...`);
                            failedExtractions++;

                            // Add a placeholder with error info
                            resumeDataList.push({
                                original_filename: resume.name,
                                name: "Processing Failed",
                                technical_skills: [],
                                experience_years: "Unknown",
                                work_experience: [`Error processing ${resume.name}: ${error.message}`],
                                education: [],
                                certifications: [],
                                soft_skills: [],
                                industry_experience: [],
                                key_achievements: [],
                                tools_technologies: [],
                                processing_error: true
                            });
                        }
                    }
                }
            }

            console.log(`Resume processing complete: ${successfulExtractions} successful, ${failedExtractions} failed`);

            if (resumeDataList.length === 0) {
                throw new Error('No resumes could be processed successfully. Please check your files and try again.');
            }

            if (failedExtractions > 0) {
                console.warn(`Warning: ${failedExtractions} resume(s) failed to process and will have limited analysis.`);
            }

            // Step 3: Perform final analysis
            console.log('Performing final analysis...');
            const analysisResponse = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    jobRequirements,
                    resumeDataList,
                    additionalCriteria: criteriaPrompt
                })
            });

            if (!analysisResponse.ok) {
                const errorText = await analysisResponse.text();
                console.error('Analysis API error response:', errorText);
                let errorData = {};
                try {
                    errorData = JSON.parse(errorText);
                } catch (parseError) {
                    console.error('Could not parse error response as JSON');
                }
                throw new Error(errorData.details || errorData.error || `Analysis API error: ${analysisResponse.status} - ${errorText}`);
            }

            const results = await analysisResponse.json();
            return results.sort((a, b) => b.score - a.score);
        } catch (error) {
            console.error('Analysis failed:', error);
            throw error;
        }
    }

    mockOpenAIResponse(resumeData) {
        // Generate mock analysis results
        return resumeData.map((resume, idx) => {
            const scores = [92, 78, 85, 67, 73, 89, 45, 91, 56, 82];
            const score = scores[idx % scores.length];

            return {
                name: resume.name,
                score: score,
                reasoning: `Based on the analysis, this candidate shows ${score > 80 ? 'excellent' : score > 60 ? 'good' : 'limited'} alignment with the job requirements.`,
                strengths: [
                    "Relevant experience in the field",
                    "Strong technical skills",
                    "Good educational background"
                ],
                weaknesses: score < 70 ? [
                    "Limited experience with specific technologies",
                    "May need additional training in certain areas"
                ] : [
                    "Minor gaps in some preferred qualifications"
                ]
            };
        }).sort((a, b) => b.score - a.score);
    }

    displayResults(results) {
        const container = document.getElementById('resultsContainer');
        const resultsSection = document.getElementById('resultsSection');
        const summaryTableBody = document.getElementById('summaryTableBody');
        const summarySection = document.querySelector('.summary-section');

        // Populate summary table
        summaryTableBody.innerHTML = results.map((result, index) => `
            <tr>
                <td class="rank-cell">
                    <span class="rank-badge">${index + 1}</span>
                </td>
                <td class="cv-name-cell" title="${result.name}">${result.name}</td>
                <td class="score-cell">
                    <span class="score-badge-table ${this.getScoreClass(result.score)}">${result.score}%</span>
                </td>
            </tr>
        `).join('');

        // Populate detailed results
        container.innerHTML = results.map(result => `
            <div class="resume-result">
                <div class="resume-header">
                    <div class="resume-name">${result.name}</div>
                    <div class="score-badge ${this.getScoreClass(result.score)}">${result.score}%</div>
                </div>
                <div class="resume-details">
                    <p><strong>Analysis:</strong> ${result.reasoning}</p>
                    <p><strong>Strengths:</strong> ${result.strengths.join(', ')}</p>
                    ${result.weaknesses.length > 0 ? `<p><strong>Areas for consideration:</strong> ${result.weaknesses.join(', ')}</p>` : ''}
                </div>
            </div>
        `).join('');

        // Show summary section and results
        if (summarySection) {
            summarySection.style.display = 'block';
            summarySection.style.opacity = '0';
            summarySection.style.transform = 'translateY(20px)';
        }

        resultsSection.style.display = 'block';

        // Animate summary section
        setTimeout(() => {
            if (summarySection) {
                summarySection.style.transition = 'all 0.6s ease-out';
                summarySection.style.opacity = '1';
                summarySection.style.transform = 'translateY(0)';
            }
        }, 100);
    }

    getScoreClass(score) {
        if (score >= 80) return 'score-high';
        if (score >= 60) return 'score-medium';
        return 'score-low';
    }

    showLoading() {
        document.getElementById('loadingState').style.display = 'block';
        document.getElementById('resultsSection').style.display = 'none';
        document.getElementById('progressSection').style.display = 'none'; // Hide progress when showing loading
    }

    hideLoading() {
        document.getElementById('loadingState').style.display = 'none';
    }

    showProgressBar() {
        const progressSection = document.getElementById('progressSection');
        const progressFill = document.getElementById('progressFill');

        // Hide loading state and results, show progress
        document.getElementById('loadingState').style.display = 'none';
        document.getElementById('resultsSection').style.display = 'none';
        progressSection.style.display = 'block';
        progressFill.classList.add('active');

        // Calculate estimated time with rate limiting considerations
        // 2 seconds per resume extraction + 1.5 seconds per API call + processing overhead
        const extractionTime = this.resumeFiles.length * 3; // Including rate limiting
        const apiProcessingTime = this.resumeFiles.length * 2.5; // Including API delays
        const analysisTime = Math.max(20, this.resumeFiles.length * 0.5); // Scale analysis time for larger batches
        const totalEstimatedTime = extractionTime + apiProcessingTime + analysisTime;
        this.updateEstimatedTime(totalEstimatedTime);

        // Start the estimated time countdown
        this.startTimeCountdown(totalEstimatedTime);

        // Reset progress to 0
        this.updateProgress(0, 100, "Initializing analysis...");
    }

    hideProgressBar() {
        const progressSection = document.getElementById('progressSection');
        const progressFill = document.getElementById('progressFill');

        progressFill.classList.remove('active');

        setTimeout(() => {
            progressSection.style.display = 'none';
            this.resetProgress();
        }, 1000);
    }

    updateProgress(currentStep, totalSteps, statusText) {
        const percentage = Math.round((currentStep / totalSteps) * 100);
        
        // Throttle updates to reduce DOM manipulation
        if (!this.lastProgressUpdate || percentage - this.lastProgressUpdate >= 2) {
            const progressFill = document.getElementById('progressFill');
            const progressText = document.getElementById('progressText');
            const progressPercentage = document.getElementById('progressPercentage');

            // Batch DOM updates
            requestAnimationFrame(() => {
                progressFill.style.width = `${percentage}%`;
                progressText.textContent = statusText;
                progressPercentage.textContent = `${percentage}%`;
            });
            
            this.lastProgressUpdate = percentage;
        }
    }

    resetProgress() {
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');
        const progressPercentage = document.getElementById('progressPercentage');

        progressFill.style.width = '0%';
        progressText.textContent = 'Initializing analysis...';
        progressPercentage.textContent = '0%';

        if (this.countdownInterval) {
            clearInterval(this.countdownInterval);
        }
    }

    updateEstimatedTime(seconds) {
        const estimatedTimeElement = document.getElementById('estimatedTime');

        if (seconds < 60) {
            estimatedTimeElement.textContent = `Estimated: ${seconds}s`;
        } else {
            const minutes = Math.floor(seconds / 60);
            const remainingSeconds = seconds % 60;
            estimatedTimeElement.textContent = `Estimated: ${minutes}m ${remainingSeconds}s`;
        }
    }

    startTimeCountdown(totalSeconds) {
        let remainingTime = totalSeconds;

        this.countdownInterval = setInterval(() => {
            remainingTime = Math.max(0, remainingTime - 1);
            this.updateEstimatedTime(remainingTime);

            if (remainingTime <= 0) {
                clearInterval(this.countdownInterval);
                document.getElementById('estimatedTime').textContent = 'Finishing up...';
            }
        }, 1000);
    }

    async downloadReport() {
        if (!this.analysisResults) return;

        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        const pageWidth = doc.internal.pageSize.getWidth();
        const pageHeight = doc.internal.pageSize.getHeight();

        // Helper function to add header background
        const addHeaderBackground = () => {
            doc.setFillColor(26, 35, 126); // #1a237e
            doc.rect(0, 0, pageWidth, 50, 'F');
        };

        // Helper function to get score color
        const getScoreColor = (score) => {
            if (score >= 80) return [40, 167, 69]; // Green
            if (score >= 60) return [255, 193, 7]; // Yellow
            return [220, 53, 69]; // Red
        };

        // Page 1 - Title page
        addHeaderBackground();

        // Title
        doc.setTextColor(255, 255, 255);
        doc.setFontSize(24);
        doc.setFont(undefined, 'bold');
        doc.text('Resume Analysis Report', pageWidth / 2, 25, { align: 'center' });

        doc.setFontSize(12);
        doc.setFont(undefined, 'normal');
        doc.text('AI-Powered Recruitment Analysis', pageWidth / 2, 35, { align: 'center' });

        // Reset text color
        doc.setTextColor(0, 0, 0);

        // Report metadata
        doc.setFontSize(14);
        doc.setFont(undefined, 'bold');
        doc.text('Report Details', 20, 70);

        doc.setFontSize(11);
        doc.setFont(undefined, 'normal');
        doc.text(`Generated on: ${new Date().toLocaleDateString()} at ${new Date().toLocaleTimeString()}`, 20, 85);
        doc.text(`Total Candidates Analyzed: ${this.analysisResults.length}`, 20, 95);
        doc.text(`Analysis completed using AI-powered evaluation`, 20, 105);

        // Summary section
        doc.setFontSize(14);
        doc.setFont(undefined, 'bold');
        doc.text('Executive Summary', 20, 130);

        // Score distribution
        const highScores = this.analysisResults.filter(r => r.score >= 80).length;
        const mediumScores = this.analysisResults.filter(r => r.score >= 60 && r.score < 80).length;
        const lowScores = this.analysisResults.filter(r => r.score < 60).length;

        doc.setFontSize(11);
        doc.setFont(undefined, 'normal');
        doc.text(`• Highly Qualified Candidates (80%+): ${highScores}`, 20, 145);
        doc.text(`• Moderately Qualified Candidates (60-79%): ${mediumScores}`, 20, 155);
        doc.text(`• Candidates Needing Consideration (<60%): ${lowScores}`, 20, 165);

        // Top candidate highlight
        if (this.analysisResults.length > 0) {
            const topCandidate = this.analysisResults[0];
            doc.setFontSize(14);
            doc.setFont(undefined, 'bold');
            doc.text('Top Candidate', 20, 190);

            doc.setFontSize(11);
            doc.setFont(undefined, 'normal');
            doc.text(`${topCandidate.name} - ${topCandidate.score}%`, 20, 205);
        }

        // Add new page for detailed results
        doc.addPage();

        // Page header for results
        addHeaderBackground();
        doc.setTextColor(255, 255, 255);
        doc.setFontSize(18);
        doc.setFont(undefined, 'bold');
        doc.text('Detailed Candidate Analysis', pageWidth / 2, 30, { align: 'center' });
        doc.setTextColor(0, 0, 0);

        let yPosition = 70;

        this.analysisResults.forEach((result, index) => {
            // Check if we need a new page
            if (yPosition > pageHeight - 80) {
                doc.addPage();
                addHeaderBackground();
                doc.setTextColor(255, 255, 255);
                doc.setFontSize(16);
                doc.setFont(undefined, 'bold');
                doc.text('Candidate Analysis (Continued)', pageWidth / 2, 30, { align: 'center' });
                doc.setTextColor(0, 0, 0);
                yPosition = 70;
            }

            // Candidate card background
            doc.setFillColor(248, 249, 250);
            doc.roundedRect(15, yPosition - 5, pageWidth - 30, 55, 3, 3, 'F');

            // Candidate rank and name
            doc.setFontSize(14);
            doc.setFont(undefined, 'bold');
            doc.setTextColor(26, 35, 126);
            doc.text(`${index + 1}. ${result.name}`, 20, yPosition + 5);

            // Score badge
            const scoreColor = getScoreColor(result.score);
            doc.setFillColor(scoreColor[0], scoreColor[1], scoreColor[2]);
            doc.roundedRect(pageWidth - 50, yPosition - 2, 35, 12, 6, 6, 'F');

            doc.setTextColor(255, 255, 255);
            doc.setFontSize(10);
            doc.setFont(undefined, 'bold');
            doc.text(`${result.score}%`, pageWidth - 32, yPosition + 6, { align: 'center' });

            // Reset text color
            doc.setTextColor(0, 0, 0);

            // Analysis text
            doc.setFontSize(10);
            doc.setFont(undefined, 'bold');
            doc.text('Analysis:', 20, yPosition + 18);

            doc.setFont(undefined, 'normal');
            const reasoningLines = doc.splitTextToSize(result.reasoning, 150);
            doc.text(reasoningLines, 20, yPosition + 26);

            // Strengths
            const strengthsY = yPosition + 26 + (reasoningLines.length * 4) + 5;
            doc.setFont(undefined, 'bold');
            doc.text('Strengths:', 20, strengthsY);

            doc.setFont(undefined, 'normal');
            const strengthsText = result.strengths.join(', ');
            const strengthsLines = doc.splitTextToSize(strengthsText, 150);
            doc.text(strengthsLines, 20, strengthsY + 8);

            // Weaknesses (if any)
            let weaknessesHeight = 0;
            if (result.weaknesses && result.weaknesses.length > 0) {
                const weaknessesY = strengthsY + 8 + (strengthsLines.length * 4) + 5;
                doc.setFont(undefined, 'bold');
                doc.text('Areas for Consideration:', 20, weaknessesY);

                doc.setFont(undefined, 'normal');
                const weaknessesText = result.weaknesses.join(', ');
                const weaknessLines = doc.splitTextToSize(weaknessesText, 150);
                doc.text(weaknessLines, 20, weaknessesY + 8);
                weaknessesHeight = 8 + (weaknessLines.length * 4);
            }

            // Update y position for next candidate
            yPosition += 60 + (reasoningLines.length * 4) + (strengthsLines.length * 4) + weaknessesHeight + 10;
        });

        // Add footer to last page
        doc.setFontSize(8);
        doc.setTextColor(100, 100, 100);
        doc.text('Generated by Resume Matcher - AI-Powered Recruitment Tool', pageWidth / 2, pageHeight - 10, { align: 'center' });
        doc.text('Rankings are based on AI analysis and should be used alongside human judgment', pageWidth / 2, pageHeight - 5, { align: 'center' });

        doc.save('resume-analysis-report.pdf');
    }

    showEmailModal() {
        document.getElementById('emailModal').style.display = 'flex';
    }

    hideEmailModal() {
        document.getElementById('emailModal').style.display = 'none';
    }

    async sendEmailReport() {
        const email = document.getElementById('hrEmail').value;
        const subject = document.getElementById('emailSubject').value;
        const message = document.getElementById('emailMessage').value;
        const sendBtn = document.getElementById('sendEmailBtn');

        if (!email) {
            alert('Please enter an email address');
            return;
        }

        if (!this.analysisResults) {
            alert('No analysis results available to send');
            return;
        }

        // Show loading state
        const originalText = sendBtn.innerHTML;
        sendBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';
        sendBtn.disabled = true;

        try {
            const response = await fetch('/api/send-email', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    to: email,
                    subject: subject,
                    message: message,
                    reportData: this.analysisResults
                })
            });

            const result = await response.json();

            if (response.ok) {
                alert(`Report successfully sent to: ${email}`);
                this.hideEmailModal();

                // Clear the form
                document.getElementById('hrEmail').value = '';
                document.getElementById('emailMessage').value = '';
            } else {
                throw new Error(result.error || 'Failed to send email');
            }
        } catch (error) {
            console.error('Email sending failed:', error);
            alert(`Failed to send email: ${error.message}`);
        } finally {
            // Restore button state
            sendBtn.innerHTML = originalText;
            sendBtn.disabled = false;
        }
    }

    showSettings() {
        const panel = document.getElementById('settingsPanel');
        panel.classList.add('active');
        this.loadCriteriaToForm();
    }

    hideSettings() {
        const panel = document.getElementById('settingsPanel');
        panel.classList.remove('active');
    }

    loadCriteria() {
        try {
            const saved = sessionStorage.getItem('hrCriteria');
            return saved ? JSON.parse(saved) : {
                technicalSkills: '',
                experienceLevel: '',
                softSkills: '',
                education: '',
                additionalCriteria: ''
            };
        } catch (error) {
            return {
                technicalSkills: '',
                experienceLevel: '',
                softSkills: '',
                education: '',
                additionalCriteria: ''
            };
        }
    }

    loadCriteriaToForm() {
        // Wait for DOM to be ready before accessing elements
        setTimeout(() => {
            const elements = {
                'technicalSkills': this.additionalCriteria.technicalSkills || '',
                'experienceLevel': this.additionalCriteria.experienceLevel || '',
                'softSkills': this.additionalCriteria.softSkills || '',
                'education': this.additionalCriteria.education || '',
                'additionalCriteria': this.additionalCriteria.additionalCriteria || ''
            };

            Object.entries(elements).forEach(([id, value]) => {
                const element = document.getElementById(id);
                if (element && element.value !== undefined) {
                    element.value = value;
                } else if (!element) {
                    console.warn(`Element with id '${id}' not found`);
                }
            });
        }, 100);
    }

    saveCriteria() {
        const getElementValue = (id) => {
            const element = document.getElementById(id);
            if (element && element.value !== undefined) {
                return element.value.trim();
            } else {
                console.warn(`Element with id '${id}' not found or has no value property`);
                return '';
            }
        };

        this.additionalCriteria = {
            technicalSkills: getElementValue('technicalSkills'),
            experienceLevel: getElementValue('experienceLevel'),
            softSkills: getElementValue('softSkills'),
            education: getElementValue('education'),
            additionalCriteria: getElementValue('additionalCriteria')
        };

        sessionStorage.setItem('hrCriteria', JSON.stringify(this.additionalCriteria));

        // Show success feedback
        const saveBtn = document.getElementById('saveCriteriaBtn');
        if (saveBtn) {
            const originalText = saveBtn.innerHTML;
            const originalColor = saveBtn.style.background;

            saveBtn.innerHTML = '<i class="fas fa-check"></i> Settings Saved!';
            saveBtn.style.background = 'linear-gradient(135deg, #28a745, #20c997)';

            setTimeout(() => {
                saveBtn.innerHTML = originalText;
                saveBtn.style.background = originalColor;
            }, 3000);
        }
    }

    clearCriteria() {
        if (confirm('Are you sure you want to clear all criteria?')) {
            this.additionalCriteria = {
                technicalSkills: '',
                experienceLevel: '',
                softSkills: '',
                education: '',
                additionalCriteria: ''
            };
            sessionStorage.removeItem('hrCriteria');
            this.loadCriteriaToForm();
        }
    }



    downloadCsv() {
        if (!this.analysisResults || this.analysisResults.length === 0) {
            alert('No analysis results available to download');
            return;
        }

        try {
            // Helper function to escape CSV fields
            const escapeCsvField = (field) => {
                if (field === null || field === undefined || field === '') {
                    return '""';
                }

                const stringField = String(field);
                // If field contains comma, newline, or quotes, wrap in quotes and escape internal quotes
                if (stringField.includes(',') || stringField.includes('\n') || stringField.includes('"')) {
                    return `"${stringField.replace(/"/g, '""')}"`;
                }
                return stringField;
            };

            // Create CSV headers
            const headers = ['Rank', 'CV Name', 'Score (%)', 'Analysis', 'Strengths', 'Areas for Consideration'];

            // Create CSV rows
            const csvRows = [
                headers.join(','), // Header row
                ...this.analysisResults.map((result, index) => {
                    const rank = index + 1;
                    const cvName = escapeCsvField(result.name || 'Unknown');
                    const score = result.score || 0;
                    const analysis = escapeCsvField(result.reasoning || 'No analysis available');
                    const strengths = escapeCsvField((result.strengths || []).join('; '));
                    const weaknesses = escapeCsvField((result.weaknesses || []).join('; '));

                    return [rank, cvName, score, analysis, strengths, weaknesses].join(',');
                })
            ];

            const csvContent = csvRows.join('\n');

            // Create blob with UTF-8 BOM for better Excel compatibility
            const BOM = '\uFEFF';
            const blob = new Blob([BOM + csvContent], { 
                type: 'text/csv;charset=utf-8;' 
            });

            // Create download link
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `resume-analysis-summary-${new Date().toISOString().split('T')[0]}.csv`;

            // Trigger download
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);

            // Clean up URL
            setTimeout(() => URL.revokeObjectURL(url), 100);

            // Show success feedback
            const csvBtn = document.getElementById('downloadCsvBtn');
            if (csvBtn) {
                const originalText = csvBtn.innerHTML;
                const originalStyle = csvBtn.style.cssText;

                csvBtn.innerHTML = '<i class="fas fa-check"></i> Downloaded!';
                csvBtn.style.background = '#28a745';
                csvBtn.style.color = 'white';

                setTimeout(() => {
                    csvBtn.innerHTML = originalText;
                    csvBtn.style.cssText = originalStyle;
                }, 2000);
            }

            console.log('CSV file downloaded successfully');

        } catch (error) {
            console.error('CSV download failed:', error);
            alert(`Failed to download CSV file: ${error.message}`);
        }
    }

    validateFileTypesBeforeAnalysis() {
        const invalidFiles = [];
        
        // Check job file
        if (this.jobFile) {
            const jobFileExtension = this.jobFile.name.toLowerCase().split('.').pop();
            if (jobFileExtension !== 'pdf' && jobFileExtension !== 'docx') {
                invalidFiles.push(`Job Description: ${this.jobFile.name} (.${jobFileExtension})`);
            }
        }
        
        // Check resume files
        this.resumeFiles.forEach(file => {
            const fileExtension = file.name.toLowerCase().split('.').pop();
            if (fileExtension !== 'pdf' && fileExtension !== 'docx') {
                invalidFiles.push(`Resume: ${file.name} (.${fileExtension})`);
            }
        });
        
        if (invalidFiles.length > 0) {
            alert(`Unsupported file formats detected:\n\n${invalidFiles.join('\n')}\n\nPlease ensure all uploaded files are in PDF or DOCX format before proceeding with analysis.`);
            return false;
        }
        
        return true;
    }

    buildCriteriaPrompt() {
        const criteria = this.additionalCriteria;
        let prompt = '';

        if (criteria.technicalSkills) {
            prompt += `\n\nIMPORTANT TECHNICAL SKILLS TO PRIORITIZE: ${criteria.technicalSkills}`;
        }
        if (criteria.experienceLevel) {
            prompt += `\n\nEXPERIENCE REQUIREMENTS: ${criteria.experienceLevel}`;
        }
        if (criteria.softSkills) {
            prompt += `\n\nSOFT SKILLS & QUALITIES: ${criteria.softSkills}`;
        }
        if (criteria.education) {
            prompt += `\n\nEDUCATION & CERTIFICATIONS: ${criteria.education}`;
        }
        if (criteria.additionalCriteria) {
            prompt += `\n\nADDITIONAL SPECIFIC REQUIREMENTS: ${criteria.additionalCriteria}`;
        }

        if (prompt) {
            prompt = `\n\n=== HR SCREENING CRITERIA (GIVE THESE HIGH EMPHASIS) ===${prompt}\n\n=== END HR CRITERIA ===`;
        }

        return prompt;
    }
}

// Initialize the app when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new ResumeMatcherApp();
});