// project-scanner.js - Run with: node project-scanner.js
// This script scans your entire project and reports what's working and what's broken

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const http = require('http');

const projectRoot = __dirname;
const outputFile = path.join(projectRoot, 'scan-report-' + new Date().toISOString().replace(/[:.]/g, '-') + '.txt');

console.log('🔍 Starting Comprehensive Project Scan...');
console.log('📁 Project Root:', projectRoot);
console.log('📄 Report will be saved to:', outputFile);

// Initialize report
let report = [];
function addToReport(section, content) {
    report.push(`\n${'='.repeat(80)}`);
    report.push(`📌 ${section}`);
    report.push(`${'='.repeat(80)}`);
    report.push(content);
}

// Helper to check if file exists
function fileExists(filePath) {
    return fs.existsSync(path.join(projectRoot, filePath));
}

// Helper to read file
function readFile(filePath) {
    try {
        return fs.readFileSync(path.join(projectRoot, filePath), 'utf8');
    } catch (e) {
        return null;
    }
}

// Helper to check if port is listening
function checkPort(port, callback) {
    const req = http.get(`http://localhost:${port}`, (res) => {
        callback(true, res.statusCode);
    }).on('error', () => {
        callback(false, null);
    });
    req.setTimeout(2000, () => {
        req.destroy();
        callback(false, null);
    });
}

// ===================================================
// SCAN 1: Project Structure
// ===================================================
let structure = '📂 Project Structure:\n\n';

// Check main directories
const dirs = [
    'public',
    'server',
    'server/routes',
    'server/services',
    'server/models',
    'data',
    'logs'
];

dirs.forEach(dir => {
    const fullPath = path.join(projectRoot, dir);
    const exists = fs.existsSync(fullPath);
    structure += `  ${exists ? '✅' : '❌'} ${dir}/\n`;
    
    // If directory exists, list its contents
    if (exists) {
        try {
            const files = fs.readdirSync(fullPath);
            files.slice(0, 5).forEach(file => {
                structure += `     📄 ${file}\n`;
            });
            if (files.length > 5) {
                structure += `     ... and ${files.length - 5} more files\n`;
            }
        } catch (e) {
            structure += `     ⚠️ Cannot read directory\n`;
        }
    }
});

addToReport('PROJECT STRUCTURE', structure);

// ===================================================
// SCAN 2: Frontend Files
// ===================================================
let frontend = '🖥️ Frontend Analysis:\n\n';

// Check main HTML file
const htmlPath = 'public/index.html';
if (fileExists(htmlPath)) {
    const htmlContent = readFile(htmlPath);
    frontend += `✅ ${htmlPath} - Found (${htmlContent ? htmlContent.length : 0} bytes)\n`;
    
    // Check for common frontend issues
    const issues = [];
    
    // Check for duplicate script tags
    const scriptTagCount = (htmlContent.match(/<script/g) || []).length;
    const scriptCloseCount = (htmlContent.match(/<\/script>/g) || []).length;
    if (scriptTagCount !== scriptCloseCount) {
        issues.push(`⚠️ Mismatched script tags: ${scriptTagCount} opening, ${scriptCloseCount} closing`);
    }
    
    // Check for nav function
    if (!htmlContent.includes('function nav(') && !htmlContent.includes('window.nav')) {
        issues.push('❌ nav function not found');
    }
    
    // Check for esc function (common error source)
    const escCount = (htmlContent.match(/const esc =/g) || []).length;
    if (escCount > 1) {
        issues.push(`❌ Duplicate esc declaration (found ${escCount} times)`);
    }
    
    // Check for PAGE_LOADED object
    if (!htmlContent.includes('const PAGE_LOADED')) {
        issues.push('⚠️ PAGE_LOADED object not found');
    }
    
    // Check for tab definitions
    const tabs = ['dashboard', 'query', 'feed', 'logs', 'mitre', 'threats', 'actors', 
                  'cve', 'zeroday', 'aisec', 'enrich', 'misp', 'playbook', 'darkweb', 'osint', 'xfeed'];
    
    tabs.forEach(tab => {
        if (htmlContent.includes(`data-tab="${tab}"`)) {
            frontend += `  ✅ Tab found: ${tab}\n`;
        }
    });
    
    if (issues.length > 0) {
        frontend += '\n🔴 Issues Found:\n';
        issues.forEach(issue => frontend += `  ${issue}\n`);
    }
} else {
    frontend += `❌ ${htmlPath} - NOT FOUND\n`;
}

// Check CSS files
const cssFiles = fs.readdirSync(path.join(projectRoot, 'public')).filter(f => f.endsWith('.css'));
if (cssFiles.length > 0) {
    frontend += `\n🎨 CSS Files:\n`;
    cssFiles.forEach(f => frontend += `  📄 ${f}\n`);
}

// Check JS files
const jsFiles = fs.readdirSync(path.join(projectRoot, 'public')).filter(f => f.endsWith('.js'));
if (jsFiles.length > 0) {
    frontend += `\n📜 JavaScript Files:\n`;
    jsFiles.forEach(f => frontend += `  📄 ${f}\n`);
}

addToReport('FRONTEND ANALYSIS', frontend);

// ===================================================
// SCAN 3: Backend Files
// ===================================================
let backend = '⚙️ Backend Analysis:\n\n';

// Check main server file
const serverPath = 'server/server.js';
if (fileExists(serverPath)) {
    const serverContent = readFile(serverPath);
    backend += `✅ ${serverPath} - Found (${serverContent ? serverContent.length : 0} bytes)\n`;
    
    // Check for common backend issues
    const issues = [];
    
    // Check for required middleware
    const requiredMiddleware = ['express', 'cors', 'helmet', 'compression', 'morgan'];
    requiredMiddleware.forEach(mw => {
        if (!serverContent.includes(`require('${mw}')`) && !serverContent.includes(`require("${mw}")`)) {
            issues.push(`⚠️ ${mw} middleware not found`);
        }
    });
    
    // Check for port definition
    const portMatch = serverContent.match(/PORT\s*=\s*process\.env\.PORT\s*\|\|\s*(\d+)/);
    if (portMatch) {
        backend += `  📍 Server port: ${portMatch[1]}\n`;
    } else {
        issues.push('❌ PORT not defined');
    }
    
    // Check for route imports
    const routeImports = (serverContent.match(/require\(['"]\.\/routes\/[^'"]+['"]\)/g) || []);
    backend += `  🛣️ Route imports found: ${routeImports.length}\n`;
    routeImports.slice(0, 5).forEach(r => backend += `     ${r}\n`);
    if (routeImports.length > 5) {
        backend += `     ... and ${routeImports.length - 5} more\n`;
    }
    
    // Check for service imports
    const serviceImports = (serverContent.match(/require\(['"]\.\/services\/[^'"]+['"]\)/g) || []);
    backend += `  🔧 Service imports found: ${serviceImports.length}\n`;
    
    // Check for cron jobs
    if (serverContent.includes('cron.schedule')) {
        backend += `  ⏰ Cron jobs configured\n`;
    }
    
    // Check for database connection
    if (serverContent.includes('sqlite3') || serverContent.includes('mongodb') || serverContent.includes('mysql')) {
        backend += `  🗄️ Database detected\n`;
    }
    
    if (issues.length > 0) {
        backend += '\n🔴 Issues Found:\n';
        issues.forEach(issue => backend += `  ${issue}\n`);
    }
} else {
    backend += `❌ ${serverPath} - NOT FOUND\n`;
}

// Check routes directory
const routesDir = 'server/routes';
if (fs.existsSync(path.join(projectRoot, routesDir))) {
    const routeFiles = fs.readdirSync(path.join(projectRoot, routesDir)).filter(f => f.endsWith('.js'));
    backend += `\n📁 Route Files (${routeFiles.length}):\n`;
    
    routeFiles.forEach(file => {
        const filePath = path.join(routesDir, file);
        const content = readFile(filePath);
        const routeCount = (content.match(/router\.(get|post|put|delete)\(/g) || []).length;
        backend += `  📄 ${file} - ${routeCount} routes\n`;
        
        // Check for common route issues
        if (content && !content.includes('module.exports')) {
            backend += `     ⚠️ Missing module.exports\n`;
        }
    });
} else {
    backend += `❌ ${routesDir} - NOT FOUND\n`;
}

// Check services directory
const servicesDir = 'server/services';
if (fs.existsSync(path.join(projectRoot, servicesDir))) {
    const serviceFiles = fs.readdirSync(path.join(projectRoot, servicesDir)).filter(f => f.endsWith('.js'));
    backend += `\n📁 Service Files (${serviceFiles.length}):\n`;
    serviceFiles.forEach(file => {
        backend += `  📄 ${file}\n`;
    });
} else {
    backend += `❌ ${servicesDir} - NOT FOUND\n`;
}

addToReport('BACKEND ANALYSIS', backend);

// ===================================================
// SCAN 4: Package.json Analysis
// ===================================================
let packages = '📦 Package.json Analysis:\n\n';

const packagePath = 'package.json';
if (fileExists(packagePath)) {
    try {
        const packageJson = JSON.parse(readFile(packagePath));
        packages += `✅ package.json found\n`;
        packages += `  📛 Name: ${packageJson.name || 'N/A'}\n`;
        packages += `  📌 Version: ${packageJson.version || 'N/A'}\n`;
        
        // Check dependencies
        const deps = packageJson.dependencies || {};
        const devDeps = packageJson.devDependencies || {};
        
        packages += `\n  📦 Dependencies (${Object.keys(deps).length}):\n`;
        const criticalDeps = ['express', 'ws', 'axios', 'cors', 'helmet', 'dotenv'];
        criticalDeps.forEach(dep => {
            const status = deps[dep] ? '✅' : '❌';
            packages += `     ${status} ${dep}${deps[dep] ? ' - ' + deps[dep] : ''}\n`;
        });
        
        packages += `\n  🔧 Dev Dependencies (${Object.keys(devDeps).length}):\n`;
        Object.keys(devDeps).slice(0, 5).forEach(dep => {
            packages += `     📦 ${dep} - ${devDeps[dep]}\n`;
        });
        
        // Check scripts
        const scripts = packageJson.scripts || {};
        packages += `\n  📜 Scripts:\n`;
        Object.entries(scripts).forEach(([name, cmd]) => {
            packages += `     ▶️ ${name}: ${cmd}\n`;
        });
        
    } catch (e) {
        packages += `❌ Error parsing package.json: ${e.message}\n`;
    }
} else {
    packages += `❌ package.json - NOT FOUND\n`;
}

addToReport('PACKAGE ANALYSIS', packages);

// ===================================================
// SCAN 5: Environment Variables
// ===================================================
let env = '🔐 Environment Variables:\n\n';

const envPath = '.env';
if (fileExists(envPath)) {
    const envContent = readFile(envPath);
    env += `✅ .env file found\n`;
    
    const requiredVars = [
        'PORT', 'AI_PROVIDER', 'GROQ_API_KEY', 'OPENAI_API_KEY',
        'VT_API_KEY', 'ABUSEIPDB_KEY', 'GITHUB_TOKEN'
    ];
    
    requiredVars.forEach(varName => {
        const exists = envContent.includes(varName + '=');
        const hasValue = exists && !envContent.includes(varName + '=your-') && !envContent.includes(varName + '=<');
        env += `  ${hasValue ? '✅' : exists ? '⚠️' : '❌'} ${varName}\n`;
    });
    
    // Check for placeholder values
    if (envContent.includes('your-') || envContent.includes('<your-')) {
        env += `\n⚠️ Placeholder values detected - some APIs may not work\n`;
    }
} else {
    env += `❌ .env file - NOT FOUND (create from .env.example)\n`;
}

// Check for .env.example
if (fileExists('.env.example')) {
    env += `\n✅ .env.example found - good for documentation\n`;
}

addToReport('ENVIRONMENT VARIABLES', env);

// ===================================================
// SCAN 6: Running Services
// ===================================================
let services = '🔄 Running Services:\n\n';

// Check if server is running on common ports
const portsToCheck = [3000, 3001, 3002, 3003, 5000, 8080];

services += 'Checking server ports...\n';
let serverRunning = false;

function checkPortsSequentially(index) {
    if (index >= portsToCheck.length) {
        if (!serverRunning) {
            services += '\n❌ No server detected on common ports\n';
            services += '   Run: npm start to start the server\n';
        }
        continueScan();
        return;
    }
    
    const port = portsToCheck[index];
    http.get(`http://localhost:${port}`, (res) => {
        serverRunning = true;
        services += `  ✅ Server running on port ${port} (HTTP ${res.statusCode})\n`;
        
        // Try to get health endpoint
        http.get(`http://localhost:${port}/health`, (healthRes) => {
            let data = '';
            healthRes.on('data', chunk => data += chunk);
            healthRes.on('end', () => {
                try {
                    const health = JSON.parse(data);
                    services += `     Health: ${health.status || 'unknown'}\n`;
                    services += `     Uptime: ${Math.floor(health.uptime / 60) || 0} minutes\n`;
                    services += `     AI Provider: ${health.aiProvider || 'none'}\n`;
                } catch (e) {
                    services += `     Health endpoint: ${healthRes.statusCode}\n`;
                }
                checkPortsSequentially(index + 1);
            });
        }).on('error', () => {
            services += `     Health endpoint: ❌ Not available\n`;
            checkPortsSequentially(index + 1);
        });
    }).on('error', () => {
        checkPortsSequentially(index + 1);
    });
}

// We'll call this after building the report
// For now, just add placeholder
services += '  (Checking ports... results will appear after scan)\n';

// ===================================================
// SCAN 7: API Endpoint Testing
// ===================================================
let apis = '🌐 API Endpoint Testing:\n\n';
apis += 'This will test common API endpoints if server is running.\n';
apis += 'Results will appear after port check.\n';

// ===================================================
// SCAN 8: Error Logs
// ===================================================
let errors = '📋 Recent Errors:\n\n';

// Check npm error log
const npmLogPath = path.join(projectRoot, 'npm-debug.log');
if (fs.existsSync(npmLogPath)) {
    const logContent = fs.readFileSync(npmLogPath, 'utf8').split('\n').slice(-20).join('\n');
    errors += `✅ npm-debug.log found (last 20 lines):\n${logContent}\n`;
}

// Check for error logs in project
const logFiles = [];
function findLogs(dir) {
    if (!fs.existsSync(dir)) return;
    const files = fs.readdirSync(dir);
    files.forEach(file => {
        const fullPath = path.join(dir, file);
        if (fs.statSync(fullPath).isDirectory()) {
            findLogs(fullPath);
        } else if (file.includes('error') || file.includes('log') || file.endsWith('.log')) {
            logFiles.push(fullPath.replace(projectRoot + path.sep, ''));
        }
    });
}
findLogs(projectRoot);

if (logFiles.length > 0) {
    errors += `\n📁 Potential log files found:\n`;
    logFiles.slice(0, 5).forEach(f => errors += `  📄 ${f}\n`);
}

addToReport('ERROR LOGS', errors);

// ===================================================
// SCAN 9: Summary
// ===================================================
let summary = '📊 SUMMARY REPORT\n\n';
summary += 'Based on file analysis:\n\n';

// Frontend summary
summary += '🖥️ FRONTEND:\n';
if (fileExists('public/index.html')) {
    const html = readFile('public/index.html') || '';
    summary += '  ✅ HTML file exists\n';
    
    if (html.includes('function nav(') || html.includes('window.nav')) {
        summary += '  ✅ nav function found\n';
    } else {
        summary += '  ❌ nav function missing\n';
    }
    
    const escCount = (html.match(/const esc =/g) || []).length;
    if (escCount === 1) {
        summary += '  ✅ esc declared once (good)\n';
    } else if (escCount > 1) {
        summary += `  ❌ esc declared ${escCount} times (duplicate error)\n`;
    }
    
    const tabCount = (html.match(/data-tab="/g) || []).length;
    summary += `  ✅ ${tabCount} tabs defined\n`;
} else {
    summary += '  ❌ index.html missing\n';
}

// Backend summary
summary += '\n⚙️ BACKEND:\n';
if (fileExists('server/server.js')) {
    summary += '  ✅ server.js exists\n';
    
    const server = readFile('server/server.js') || '';
    if (server.includes('app.listen')) {
        summary += '  ✅ Server has listen() function\n';
    } else {
        summary += '  ❌ No app.listen() found\n';
    }
    
    const routeCount = (server.match(/app\.use\(/g) || []).length;
    summary += `  ✅ ${routeCount} routes mounted\n`;
} else {
    summary += '  ❌ server.js missing\n';
}

// Package summary
if (fileExists('package.json')) {
    try {
        const pkg = JSON.parse(readFile('package.json'));
        summary += '\n📦 PACKAGES:\n';
        summary += `  ✅ ${Object.keys(pkg.dependencies || {}).length} dependencies\n`;
        summary += `  ✅ ${Object.keys(pkg.devDependencies || {}).length} dev dependencies\n`;
    } catch (e) {
        summary += '  ❌ Error reading package.json\n';
    }
}

// Environment summary
if (fileExists('.env')) {
    const env = readFile('.env') || '';
    const hasKeys = !env.includes('your-') && env.length > 100;
    summary += '\n🔐 ENVIRONMENT:\n';
    summary += `  ${hasKeys ? '✅' : '⚠️'} .env file ${hasKeys ? 'has real keys' : 'has placeholder values'}\n`;
} else {
    summary += '\n🔐 ENVIRONMENT:\n';
    summary += '  ❌ No .env file\n';
}

addToReport('SUMMARY', summary);

// ===================================================
// Write report and check ports
// ===================================================
function continueScan() {
    // Add port check results to services section
    services += '\n' + (serverRunning ? '✅ Server is running' : '❌ No server detected');
    
    // Add API test results if server is running
    if (serverRunning) {
        apis += '\nTesting common API endpoints...\n';
        // This would need async handling, but we'll add placeholder
        apis += 'Run the server and test manually with curl or browser.\n';
    }
    
    // Replace the services section in report
    const servicesIndex = report.findIndex(s => s.includes('🔄 Running Services'));
    if (servicesIndex !== -1) {
        report[servicesIndex + 2] = services;
    }
    
    // Replace APIs section
    const apisIndex = report.findIndex(s => s.includes('🌐 API Endpoint Testing'));
    if (apisIndex !== -1) {
        report[apisIndex + 2] = apis;
    }
    
    // Write final report
    const fullReport = report.join('\n');
    fs.writeFileSync(outputFile, fullReport, 'utf8');
    
    console.log('\n' + '='.repeat(60));
    console.log('✅ SCAN COMPLETE!');
    console.log('='.repeat(60));
    console.log('\n📄 Report saved to:', outputFile);
    console.log('\n📋 Quick Summary:');
    console.log('  • Frontend:', fileExists('public/index.html') ? '✅ Found' : '❌ Missing');
    console.log('  • Backend:', fileExists('server/server.js') ? '✅ Found' : '❌ Missing');
    console.log('  • Package.json:', fileExists('package.json') ? '✅ Found' : '❌ Missing');
    console.log('  • .env:', fileExists('.env') ? '✅ Found' : '❌ Missing');
    console.log('  • Server running:', serverRunning ? '✅ Yes' : '❌ No');
    console.log('\n🔍 Check the full report for details.\n');
}

// Start port checking
checkPortsSequentially(0);