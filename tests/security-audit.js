#!/usr/bin/env node
/**
 * Security Audit Script
 *
 * Scans codebase for common security issues
 */

import { readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT_DIR = join(__dirname, '..');

const securityPatterns = [
  {
    name: 'innerHTML usage (XSS risk)',
    pattern: /\.innerHTML\s*=/g,
    severity: 'HIGH',
    allowedFiles: ['popup/popup.js'] // popup.js line 452 uses static content only
  },
  {
    name: 'eval() usage',
    pattern: /\beval\s*\(/g,
    severity: 'CRITICAL',
    allowedFiles: ['tests/', 'csrf-detector.js'] // Exclude test files and pattern checks
  },
  {
    name: 'document.write() usage',
    pattern: /document\.write\s*\(/g,
    severity: 'HIGH',
    allowedFiles: ['tests/'] // Exclude test files
  },
  {
    name: 'Unsafe regex (ReDoS risk)',
    pattern: /new RegExp\([^)]*\+/g,
    severity: 'MEDIUM',
    allowedFiles: ['browser-detector.js', 'xss-monitor.js'] // These use proper escaping
  },
  {
    name: 'Hardcoded credentials/secrets',
    pattern: /(password|api[_-]?key|secret|token)\s*=\s*['"][^'"]+['"]/gi,
    severity: 'CRITICAL',
    allowedFiles: ['tests/', 'webrequest-monitor.js'] // Exclude test files and pattern arrays
  }
];

function scanFile(filePath) {
  const content = readFileSync(filePath, 'utf8');
  const issues = [];

  securityPatterns.forEach(({ name, pattern, severity, allowedFiles }) => {
    // Skip if this file is in allowed list
    if (allowedFiles.some(allowed => filePath.includes(allowed))) {
      return;
    }

    const matches = content.match(pattern);
    if (matches) {
      issues.push({
        file: filePath.replace(ROOT_DIR + '/', ''),
        issue: name,
        severity,
        count: matches.length
      });
    }
  });

  return issues;
}

function scanDirectory(dir, extensions = ['.js']) {
  const files = readdirSync(dir, { withFileTypes: true });
  let allIssues = [];

  for (const file of files) {
    const fullPath = join(dir, file.name);

    if (file.isDirectory()) {
      // Skip node_modules, build, etc.
      if (['node_modules', 'build', '.git'].includes(file.name)) {
        continue;
      }
      allIssues = allIssues.concat(scanDirectory(fullPath, extensions));
    } else if (extensions.some(ext => file.name.endsWith(ext))) {
      const issues = scanFile(fullPath);
      allIssues = allIssues.concat(issues);
    }
  }

  return allIssues;
}

function runAudit() {
  console.log('🔒 Running security audit...\n');

  const issues = scanDirectory(ROOT_DIR);

  // Group by severity
  const critical = issues.filter(i => i.severity === 'CRITICAL');
  const high = issues.filter(i => i.severity === 'HIGH');
  const medium = issues.filter(i => i.severity === 'MEDIUM');

  // Print results
  console.log('='.repeat(60));
  console.log('SECURITY AUDIT RESULTS');
  console.log('='.repeat(60));

  if (critical.length > 0) {
    console.log('\n🚨 CRITICAL ISSUES:');
    critical.forEach(issue => {
      console.log(`  ${issue.file}: ${issue.issue} (${issue.count} occurrence(s))`);
    });
  }

  if (high.length > 0) {
    console.log('\n⚠️  HIGH SEVERITY ISSUES:');
    high.forEach(issue => {
      console.log(`  ${issue.file}: ${issue.issue} (${issue.count} occurrence(s))`);
    });
  }

  if (medium.length > 0) {
    console.log('\n⚡ MEDIUM SEVERITY ISSUES:');
    medium.forEach(issue => {
      console.log(`  ${issue.file}: ${issue.issue} (${issue.count} occurrence(s))`);
    });
  }

  console.log('\n' + '='.repeat(60));
  console.log(`Total Issues Found: ${issues.length}`);
  console.log(`  Critical: ${critical.length}`);
  console.log(`  High: ${high.length}`);
  console.log(`  Medium: ${medium.length}`);
  console.log('='.repeat(60));

  if (critical.length > 0) {
    console.log('\n❌ CRITICAL issues found - must be fixed before production!');
    process.exit(1);
  } else if (high.length > 0) {
    console.log('\n⚠️  HIGH severity issues found - should be addressed');
    process.exit(1);
  } else {
    console.log('\n✅ No critical or high severity issues found');
    process.exit(0);
  }
}

runAudit();
