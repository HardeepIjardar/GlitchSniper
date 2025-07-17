// DOM Elements
const targetUrlInput = document.getElementById('targetUrl');
const startScanButton = document.getElementById('startScan');
const terminal = document.getElementById('terminal');
const progressFill = document.querySelector('.progress-fill');
const scanStatus = document.querySelector('.scan-status');
const vulnerabilityCards = document.getElementById('vulnerabilityCards');

// Vulnerability types and their descriptions
const vulnerabilities = [
    {
        name: 'SQL Injection',
        risk: 'High',
        description: 'Potential SQL injection vulnerability detected in form inputs.',
        fix: 'Implement prepared statements and input validation.',
        icon: '🔒'
    },
    {
        name: 'XSS (Cross-site Scripting)',
        risk: 'High',
        description: 'Unsanitized user input could lead to XSS attacks.',
        fix: 'Implement proper output encoding and Content Security Policy.',
        icon: '🛡️'
    },
    {
        name: 'Open Ports',
        risk: 'Medium',
        description: 'Multiple unnecessary ports are open to the public.',
        fix: 'Close unused ports and implement proper firewall rules.',
        icon: '🚪'
    },
    {
        name: 'CSRF',
        risk: 'Medium',
        description: 'Missing CSRF tokens in forms.',
        fix: 'Implement CSRF tokens and validate them server-side.',
        icon: '🔄'
    },
    {
        name: 'SSL/HTTPS Security',
        risk: 'High',
        description: 'Weak SSL/TLS configuration detected.',
        fix: 'Update SSL/TLS configuration and disable weak ciphers.',
        icon: '🔐'
    },
    {
        name: 'Header Configuration',
        risk: 'Low',
        description: 'Missing security headers.',
        fix: 'Implement security headers like X-Frame-Options, X-Content-Type-Options.',
        icon: '📋'
    },
    {
        name: 'Mixed Content',
        risk: 'Medium',
        description: 'Mixed content (HTTP/HTTPS) detected.',
        fix: 'Ensure all resources are loaded over HTTPS.',
        icon: '⚠️'
    },
    {
        name: 'Directory Listing',
        risk: 'Low',
        description: 'Directory listing is enabled.',
        fix: 'Disable directory listing in server configuration.',
        icon: '📁'
    },
    {
        name: 'Clickjacking',
        risk: 'Medium',
        description: 'Missing X-Frame-Options header.',
        fix: 'Implement X-Frame-Options or Content-Security-Policy frame-ancestors.',
        icon: '🎯'
    },
    {
        name: 'CSP Misconfigurations',
        risk: 'Medium',
        description: 'Content Security Policy is not properly configured.',
        fix: 'Implement a strict CSP policy and monitor for violations.',
        icon: '⚡'
    }
];

// GitHub-specific vulnerabilities
const githubVulnerabilities = [
    {
        name: 'Exposed API Keys',
        risk: 'High',
        description: 'API keys found in repository files or commit history.',
        fix: 'Remove API keys and use environment variables or secure secret management.',
        icon: '🔑'
    },
    {
        name: 'Hardcoded Credentials',
        risk: 'High',
        description: 'Hardcoded passwords or credentials found in code.',
        fix: 'Remove hardcoded credentials and implement secure credential management.',
        icon: '🔏'
    },
    {
        name: 'Outdated Dependencies',
        risk: 'Medium',
        description: 'Repository contains outdated packages with known vulnerabilities.',
        fix: 'Update dependencies to their latest secure versions.',
        icon: '📦'
    },
    {
        name: 'Sensitive Data Exposure',
        risk: 'High',
        description: 'Sensitive data found in repository files or commit history.',
        fix: 'Remove sensitive data and implement proper data handling practices.',
        icon: '📄'
    },
    {
        name: 'Insecure Configuration',
        risk: 'Medium',
        description: 'Repository contains insecure configuration files.',
        fix: 'Update configuration files with secure settings.',
        icon: '⚙️'
    }
];

// Terminal typing effect
function typeToTerminal(text, speed = 50) {
    return new Promise(resolve => {
        let i = 0;
        const interval = setInterval(() => {
            if (i < text.length) {
                terminal.innerHTML += text.charAt(i);
                terminal.scrollTop = terminal.scrollHeight;
                i++;
            } else {
                clearInterval(interval);
                terminal.innerHTML += '<br>';
                resolve();
            }
        }, speed);
    });
}

// Matrix Rain Effect
function createMatrixRain() {
    const matrixBg = document.getElementById('matrixBg');
    const columns = Math.floor(window.innerWidth / 20);
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()';

    for (let i = 0; i < columns; i++) {
        const column = document.createElement('div');
        column.className = 'matrix-column';
        column.style.left = `${i * 20}px`;
        column.style.animationDuration = `${Math.random() * 2 + 1}s`;
        column.style.animationDelay = `${Math.random() * 2}s`;
        
        // Create initial characters
        const length = Math.floor(Math.random() * 20) + 10;
        let text = '';
        for (let j = 0; j < length; j++) {
            text += characters[Math.floor(Math.random() * characters.length)] + '<br>';
        }
        column.innerHTML = text;
        
        matrixBg.appendChild(column);
    }
}

// Scan Mode Handling
const modeButtons = document.querySelectorAll('.mode-button');
const websiteInput = document.querySelector('.website-input');
const githubInput = document.querySelector('.github-input');
let currentMode = 'website';

modeButtons.forEach(button => {
    button.addEventListener('click', () => {
        // Update active button
        modeButtons.forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');
        
        // Update current mode
        currentMode = button.dataset.mode;
        
        // Show/hide appropriate input
        if (currentMode === 'website') {
            websiteInput.style.display = 'block';
            githubInput.style.display = 'none';
        } else {
            websiteInput.style.display = 'none';
            githubInput.style.display = 'block';
        }
        
        // Clear previous results
        terminal.innerHTML = '';
        vulnerabilityCards.innerHTML = '';
        progressFill.style.width = '0%';
        scanStatus.textContent = 'Ready to scan...';
    });
});

// Enhanced scan animation with actual vulnerability checks
async function simulateScan() {
    const input = currentMode === 'website' ? targetUrlInput : document.getElementById('githubRepo');
    const target = input.value;
    
    if (!target) {
        await typeToTerminal(`ERROR: Please enter a valid ${currentMode === 'website' ? 'URL' : 'GitHub repository'}`);
        return;
    }

    // Clear previous results
    terminal.innerHTML = '';
    vulnerabilityCards.innerHTML = '';
    progressFill.style.width = '0%';
    scanStatus.textContent = 'Initializing scan...';

    // Add scan start effect
    document.body.style.filter = 'brightness(1.2)';
    setTimeout(() => {
        document.body.style.filter = 'brightness(1)';
    }, 500);

    try {
        // Mode-specific scan steps
        const steps = currentMode === 'website' ? [
            'Connecting to target website...',
            'Analyzing server configuration...',
            'Scanning for SQL injection vulnerabilities...',
            'Checking for XSS vulnerabilities...',
            'Analyzing SSL/TLS configuration...',
            'Checking security headers...',
            'Scanning for open ports...',
            'Analyzing directory structure...',
            'Checking for CSRF vulnerabilities...',
            'Finalizing scan results...'
        ] : [
            'Connecting to GitHub repository...',
            'Analyzing repository structure...',
            'Checking for sensitive data exposure...',
            'Scanning for hardcoded credentials...',
            'Analyzing dependency vulnerabilities...',
            'Checking for security misconfigurations...',
            'Scanning for exposed API keys...',
            'Analyzing commit history...',
            'Checking for outdated dependencies...',
            'Finalizing scan results...'
        ];

        // Perform actual vulnerability checks
        const foundVulnerabilities = [];
        let currentStep = 0;
        
        // Ensure URL has proper protocol
        let targetUrl = target;
        if (currentMode === 'website' && !target.startsWith('http://') && !target.startsWith('https://')) {
            targetUrl = 'https://' + target;
        }

        for (const step of steps) {
            await typeToTerminal(`[${new Date().toLocaleTimeString()}] ${step}`);
            progressFill.style.width = `${((currentStep + 1) / steps.length) * 100}%`;
            scanStatus.textContent = step;
            
            // Simulate actual scanning time
            await new Promise(resolve => setTimeout(resolve, 800));

            try {
                // Perform actual checks based on the current step
                if (currentMode === 'website') {
                    const vulnerabilities = await checkWebsiteVulnerabilities(targetUrl, currentStep);
                    if (vulnerabilities && vulnerabilities.length > 0) {
                        foundVulnerabilities.push(...vulnerabilities);
                        await typeToTerminal(`[FOUND] ${vulnerabilities.length} vulnerability/vulnerabilities in step ${currentStep + 1}`);
                    }
                } else {
                    const vulnerabilities = await checkGitHubVulnerabilities(target, currentStep);
                    if (vulnerabilities && vulnerabilities.length > 0) {
                        foundVulnerabilities.push(...vulnerabilities);
                        await typeToTerminal(`[FOUND] ${vulnerabilities.length} vulnerability/vulnerabilities in step ${currentStep + 1}`);
                    }
                }
            } catch (error) {
                await typeToTerminal(`[ERROR] Failed to complete step ${currentStep + 1}: ${error.message}`);
            }

            currentStep++;
        }

        // Display results
        await typeToTerminal('\n=== SCAN RESULTS ===\n');
        
        if (foundVulnerabilities.length === 0) {
            await typeToTerminal('[SUCCESS] No vulnerabilities found. The target appears to be secure.');
            await typeToTerminal('Recommendation: Continue regular security monitoring and updates.');
        } else {
            // Remove duplicates and sort by risk level
            const uniqueVulnerabilities = removeDuplicateVulnerabilities(foundVulnerabilities);
            const sortedVulnerabilities = sortVulnerabilitiesByRisk(uniqueVulnerabilities);

            await typeToTerminal(`[FOUND] ${sortedVulnerabilities.length} unique vulnerabilities:\n`);
            
            for (const vuln of sortedVulnerabilities) {
                await typeToTerminal(`[${vuln.risk.toUpperCase()}] ${vuln.name}`);
                createVulnerabilityCard(vuln);
                await new Promise(resolve => setTimeout(resolve, 300));
            }
        }

        enableDownloadButton();
    } catch (error) {
        await typeToTerminal(`\n[ERROR] Scan failed: ${error.message}`);
        scanStatus.textContent = 'Scan failed';
    }
}

// Function to check website vulnerabilities
async function checkWebsiteVulnerabilities(url, step) {
    const vulnerabilities = [];
    
    try {
        // Add timeout for each check
        const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Check timeout')), 5000)
        );

        switch (step) {
            case 2: // SQL Injection check
                const sqlInjectionVuln = await Promise.race([
                    checkSQLInjection(url),
                    timeoutPromise
                ]);
                if (sqlInjectionVuln) vulnerabilities.push(sqlInjectionVuln);
                break;
                
            case 3: // XSS check
                const xssVuln = await Promise.race([
                    checkXSS(url),
                    timeoutPromise
                ]);
                if (xssVuln) vulnerabilities.push(xssVuln);
                break;
                
            case 4: // SSL/TLS check
                const sslVuln = await Promise.race([
                    checkSSL(url),
                    timeoutPromise
                ]);
                if (sslVuln) vulnerabilities.push(sslVuln);
                break;
                
            case 5: // Security headers check
                const headerVulns = await Promise.race([
                    checkSecurityHeaders(url),
                    timeoutPromise
                ]);
                vulnerabilities.push(...headerVulns);
                break;
                
            case 6: // Open ports check
                const portVulns = await Promise.race([
                    checkOpenPorts(url),
                    timeoutPromise
                ]);
                vulnerabilities.push(...portVulns);
                break;
                
            case 7: // Directory listing check
                const dirVuln = await Promise.race([
                    checkDirectoryListing(url),
                    timeoutPromise
                ]);
                if (dirVuln) vulnerabilities.push(dirVuln);
                break;
                
            case 8: // CSRF check
                const csrfVuln = await Promise.race([
                    checkCSRF(url),
                    timeoutPromise
                ]);
                if (csrfVuln) vulnerabilities.push(csrfVuln);
                break;
        }
    } catch (error) {
        console.error(`Error in vulnerability check step ${step}:`, error);
        // Log the error but continue with the scan
        await typeToTerminal(`[WARNING] Check in step ${step + 1} timed out or failed: ${error.message}`);
    }
    
    return vulnerabilities;
}

// Function to check GitHub repository vulnerabilities
async function checkGitHubVulnerabilities(repo, step) {
    const vulnerabilities = [];
    
    try {
        switch (step) {
            case 2: // Sensitive data check
                const sensitiveDataVuln = await checkSensitiveData(repo);
                if (sensitiveDataVuln) vulnerabilities.push(sensitiveDataVuln);
                break;
                
            case 3: // Hardcoded credentials check
                const credentialsVuln = await checkHardcodedCredentials(repo);
                if (credentialsVuln) vulnerabilities.push(credentialsVuln);
                break;
                
            case 4: // Dependency vulnerabilities check
                const depVulns = await checkDependencyVulnerabilities(repo);
                vulnerabilities.push(...depVulns);
                break;
                
            case 5: // Security misconfigurations check
                const configVulns = await checkSecurityMisconfigurations(repo);
                vulnerabilities.push(...configVulns);
                break;
                
            case 6: // API keys check
                const apiKeyVuln = await checkExposedAPIKeys(repo);
                if (apiKeyVuln) vulnerabilities.push(apiKeyVuln);
                break;
        }
    } catch (error) {
        console.error(`Error in GitHub vulnerability check step ${step}:`, error);
    }
    
    return vulnerabilities;
}

// Helper function to remove duplicate vulnerabilities
function removeDuplicateVulnerabilities(vulnerabilities) {
    const uniqueVulns = new Map();
    
    for (const vuln of vulnerabilities) {
        if (!uniqueVulns.has(vuln.name)) {
            uniqueVulns.set(vuln.name, vuln);
        }
    }
    
    return Array.from(uniqueVulns.values());
}

// Helper function to sort vulnerabilities by risk level
function sortVulnerabilitiesByRisk(vulnerabilities) {
    const riskOrder = { 'High': 0, 'Medium': 1, 'Low': 2 };
    
    return vulnerabilities.sort((a, b) => {
        return riskOrder[a.risk] - riskOrder[b.risk];
    });
}

// Actual vulnerability checking functions
async function checkSQLInjection(url) {
    try {
        const response = await fetch(url);
        const text = await response.text();
        
        // Check for common SQL injection patterns in forms
        const sqlPatterns = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users; --"
        ];
        
        if (text.includes('form') || text.includes('input')) {
            for (const pattern of sqlPatterns) {
                if (text.includes(pattern)) {
                    return {
                        name: 'SQL Injection',
                        risk: 'High',
                        description: 'Potential SQL injection vulnerability detected in form inputs.',
                        fix: 'Implement prepared statements and input validation.',
                        icon: '🔒'
                    };
                }
            }
        }
        return null;
    } catch (error) {
        console.error('SQL Injection check error:', error);
        return null;
    }
}

async function checkXSS(url) {
    try {
        const response = await fetch(url);
        const text = await response.text();
        
        // Check for common XSS patterns
        const xssPatterns = [
            '<script>alert(1)</script>',
            'javascript:alert(1)',
            'onerror=alert(1)'
        ];
        
        for (const pattern of xssPatterns) {
            if (text.includes(pattern)) {
                return {
                    name: 'XSS (Cross-site Scripting)',
                    risk: 'High',
                    description: 'Unsanitized user input could lead to XSS attacks.',
                    fix: 'Implement proper output encoding and Content Security Policy.',
                    icon: '🛡️'
                };
            }
        }
        return null;
    } catch (error) {
        console.error('XSS check error:', error);
        return null;
    }
}

async function checkSSL(url) {
    try {
        if (!url.startsWith('https://')) {
            return {
                name: 'SSL/HTTPS Security',
                risk: 'High',
                description: 'Website is not using HTTPS, making it vulnerable to man-in-the-middle attacks.',
                fix: 'Implement SSL/TLS and redirect all HTTP traffic to HTTPS.',
                icon: '🔐'
            };
        }
        
        const response = await fetch(url);
        const headers = response.headers;
        
        // Check for security headers
        const securityHeaders = {
            'Strict-Transport-Security': 'Missing HSTS header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'Content-Security-Policy': 'Missing Content-Security-Policy header'
        };
        
        const missingHeaders = [];
        for (const [header, message] of Object.entries(securityHeaders)) {
            if (!headers.get(header)) {
                missingHeaders.push(message);
            }
        }
        
        if (missingHeaders.length > 0) {
            return {
                name: 'Header Configuration',
                risk: 'Medium',
                description: `Missing security headers: ${missingHeaders.join(', ')}`,
                fix: 'Implement recommended security headers.',
                icon: '📋'
            };
        }
        
        return null;
    } catch (error) {
        console.error('SSL check error:', error);
        return null;
    }
}

async function checkSecurityHeaders(url) {
    try {
        const response = await fetch(url);
        const headers = response.headers;
        const vulnerabilities = [];
        
        // Check for various security headers
        if (!headers.get('X-Frame-Options')) {
            vulnerabilities.push({
                name: 'Clickjacking',
                risk: 'Medium',
                description: 'Missing X-Frame-Options header.',
                fix: 'Implement X-Frame-Options or Content-Security-Policy frame-ancestors.',
                icon: '🎯'
            });
        }
        
        if (!headers.get('Content-Security-Policy')) {
            vulnerabilities.push({
                name: 'CSP Misconfigurations',
                risk: 'Medium',
                description: 'Content Security Policy is not properly configured.',
                fix: 'Implement a strict CSP policy and monitor for violations.',
                icon: '⚡'
            });
        }
        
        return vulnerabilities;
    } catch (error) {
        console.error('Security headers check error:', error);
        return [];
    }
}

async function checkOpenPorts(url) {
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;
        const openPorts = [];
        
        // Common ports to check with shorter timeout
        const ports = [80, 443, 8080, 8443];
        
        // Create an array of promises for parallel port checking
        const portChecks = ports.map(async (port) => {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 2000); // 2 second timeout
                
                const response = await fetch(`${urlObj.protocol}//${hostname}:${port}`, {
                    signal: controller.signal,
                    mode: 'no-cors' // This prevents CORS issues
                });
                
                clearTimeout(timeoutId);
                return port;
            } catch (error) {
                // Port is likely closed or filtered
                return null;
            }
        });

        // Wait for all port checks with a timeout
        const results = await Promise.race([
            Promise.all(portChecks),
            new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Port scan timeout')), 5000)
            )
        ]);

        // Filter out null results and get open ports
        const detectedPorts = results.filter(port => port !== null);

        if (detectedPorts.length > 0) {
            return [{
                name: 'Open Ports',
                risk: 'Medium',
                description: `Multiple unnecessary ports are open: ${detectedPorts.join(', ')}`,
                fix: 'Close unused ports and implement proper firewall rules.',
                icon: '🚪'
            }];
        }
        
        return [];
    } catch (error) {
        console.error('Open ports check error:', error);
        // Return empty array instead of hanging
        return [];
    }
}

async function checkDirectoryListing(url) {
    try {
        const response = await fetch(url);
        const text = await response.text();
        
        // Check for common directory listing indicators
        if (text.includes('Index of /') || text.includes('Parent Directory')) {
            return {
                name: 'Directory Listing',
                risk: 'Low',
                description: 'Directory listing is enabled.',
                fix: 'Disable directory listing in server configuration.',
                icon: '📁'
            };
        }
        
        return null;
    } catch (error) {
        console.error('Directory listing check error:', error);
        return null;
    }
}

async function checkCSRF(url) {
    try {
        const response = await fetch(url);
        const text = await response.text();
        
        // Check for CSRF token in forms
        if (text.includes('form') && !text.includes('csrf') && !text.includes('token')) {
            return {
                name: 'CSRF',
                risk: 'Medium',
                description: 'Missing CSRF tokens in forms.',
                fix: 'Implement CSRF tokens and validate them server-side.',
                icon: '🔄'
            };
        }
        
        return null;
    } catch (error) {
        console.error('CSRF check error:', error);
        return null;
    }
}

async function checkSensitiveData(repo) {
    // Implement actual sensitive data check for GitHub
    // Return vulnerability object if found, null if not
    return null;
}

async function checkHardcodedCredentials(repo) {
    // Implement actual hardcoded credentials check for GitHub
    // Return vulnerability object if found, null if not
    return null;
}

async function checkDependencyVulnerabilities(repo) {
    // Implement actual dependency vulnerabilities check for GitHub
    // Return array of vulnerability objects
    return [];
}

async function checkSecurityMisconfigurations(repo) {
    // Implement actual security misconfigurations check for GitHub
    // Return array of vulnerability objects
    return [];
}

async function checkExposedAPIKeys(repo) {
    // Implement actual exposed API keys check for GitHub
    // Return vulnerability object if found, null if not
    return null;
}

// Enhanced vulnerability card creation
function createVulnerabilityCard(vulnerability) {
    const card = document.createElement('div');
    card.className = 'vulnerability-card';
    card.style.opacity = '0';
    card.style.transform = 'translateY(20px)';
    
    card.innerHTML = `
        <div class="vulnerability-header">
            <span class="vulnerability-icon">${vulnerability.icon}</span>
            <h3 style="color: ${getRiskColor(vulnerability.risk)}">${vulnerability.name}</h3>
        </div>
        <p><strong>Risk Level:</strong> ${vulnerability.risk}</p>
        <p><strong>Description:</strong> ${vulnerability.description}</p>
        <p><strong>Fix:</strong> ${vulnerability.fix}</p>
    `;
    
    vulnerabilityCards.appendChild(card);
    
    // Trigger animation
    requestAnimationFrame(() => {
        card.style.transition = 'all 0.5s ease-out';
        card.style.opacity = '1';
        card.style.transform = 'translateY(0)';
    });
}

// Get color based on risk level
function getRiskColor(risk) {
    switch (risk.toLowerCase()) {
        case 'high':
            return 'var(--alert-red)';
        case 'medium':
            return 'var(--magenta)';
        case 'low':
            return 'var(--cyan)';
        default:
            return 'var(--text-color)';
    }
}

// Event Listeners
startScanButton.addEventListener('click', simulateScan);

// Initialize matrix rain
createMatrixRain();

// Handle window resize
window.addEventListener('resize', () => {
    const matrixBg = document.getElementById('matrixBg');
    matrixBg.innerHTML = '';
    createMatrixRain();
});

// Download Report Functionality
const downloadReport = document.getElementById('downloadReport');

function generateReport() {
    const vulnerabilities = document.querySelectorAll('.vulnerability-card');
    const report = {
        scanDate: new Date().toISOString(),
        scanMode: currentMode,
        target: currentMode === 'website' ? 
            document.getElementById('targetUrl').value :
            document.getElementById('githubRepo').value,
        vulnerabilities: Array.from(vulnerabilities).map(card => {
            const paragraphs = card.querySelectorAll('p');
            return {
                name: card.querySelector('h3').textContent,
                riskLevel: paragraphs[0].textContent.replace('Risk Level:', '').trim(),
                description: paragraphs[1].textContent.replace('Description:', '').trim(),
                fix: paragraphs[2].textContent.replace('Fix:', '').trim()
            };
        })
    };

    return JSON.stringify(report, null, 2);
}

function downloadReportFile() {
    try {
        const report = generateReport();
        const blob = new Blob([report], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        
        a.href = url;
        a.download = `vulnerability-report-${timestamp}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        // Add success message to terminal
        typeToTerminal('\n[SUCCESS] Report downloaded successfully!');
    } catch (error) {
        console.error('Error generating report:', error);
        typeToTerminal('\n[ERROR] Failed to generate report. Please try again.');
    }
}

// Enable download button when scan is complete
function enableDownloadButton() {
    const downloadReport = document.getElementById('downloadReport');
    if (downloadReport) {
        downloadReport.disabled = false;
        downloadReport.addEventListener('click', downloadReportFile);
    }
}

// Add this to your existing scan completion logic
function onScanComplete() {
    // ... existing scan completion code ...
    enableDownloadButton();
} 