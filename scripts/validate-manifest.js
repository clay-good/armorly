#!/usr/bin/env node
/**
 * Manifest Validator
 *
 * Validates manifest.json for common issues and Chrome Web Store requirements
 */

import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const MANIFEST_PATH = join(__dirname, '..', 'manifest.json');

function validateManifest() {
  console.log('🔍 Validating manifest.json...\n');

  let hasErrors = false;
  let hasWarnings = false;

  // Read manifest
  let manifest;
  try {
    const content = readFileSync(MANIFEST_PATH, 'utf8');
    manifest = JSON.parse(content);
  } catch (error) {
    console.error('❌ ERROR: Failed to parse manifest.json');
    console.error(error.message);
    process.exit(1);
  }

  // Check required fields
  const required = ['manifest_version', 'name', 'version', 'description'];
  required.forEach(field => {
    if (!manifest[field]) {
      console.error(`❌ ERROR: Missing required field: ${field}`);
      hasErrors = true;
    }
  });

  // Validate manifest version
  if (manifest.manifest_version !== 3) {
    console.error('❌ ERROR: manifest_version must be 3');
    hasErrors = true;
  }

  // Validate version format
  const versionPattern = /^\d+\.\d+\.\d+(\.\d+)?$/;
  if (!versionPattern.test(manifest.version)) {
    console.error(`❌ ERROR: Invalid version format: ${manifest.version}`);
    console.error('   Expected format: X.Y.Z or X.Y.Z.W');
    hasErrors = true;
  }

  // Check description length
  if (manifest.description && manifest.description.length > 132) {
    console.warn(`⚠️  WARNING: Description too long (${manifest.description.length} chars, max 132)`);
    hasWarnings = true;
  }

  // Check icons
  if (!manifest.icons || !manifest.icons['128']) {
    console.error('❌ ERROR: Missing required 128x128 icon');
    hasErrors = true;
  }

  // Validate permissions
  if (manifest.permissions && manifest.permissions.includes('scripting')) {
    console.warn('⚠️  WARNING: "scripting" permission found but not used in codebase');
    hasWarnings = true;
  }

  // Check for overly broad host permissions
  if (manifest.host_permissions && manifest.host_permissions.includes('<all_urls>')) {
    console.warn('⚠️  WARNING: Using <all_urls> permission - Chrome Web Store may require justification');
    hasWarnings = true;
  }

  // Validate service worker
  if (!manifest.background || !manifest.background.service_worker) {
    console.error('❌ ERROR: Missing background service worker');
    hasErrors = true;
  }

  // Check for deprecated fields
  const deprecated = ['browser_action', 'page_action', 'background.scripts', 'background.persistent'];
  deprecated.forEach(field => {
    const parts = field.split('.');
    let obj = manifest;
    for (const part of parts) {
      if (obj && obj[part] !== undefined) {
        console.warn(`⚠️  WARNING: Deprecated field found: ${field}`);
        hasWarnings = true;
        break;
      }
      obj = obj?.[part];
    }
  });

  // Summary
  console.log('\n' + '='.repeat(50));
  if (!hasErrors && !hasWarnings) {
    console.log('✅ Manifest validation passed with no issues!');
    process.exit(0);
  } else if (!hasErrors && hasWarnings) {
    console.log('✅ Manifest validation passed with warnings');
    process.exit(0);
  } else {
    console.log('❌ Manifest validation failed with errors');
    process.exit(1);
  }
}

validateManifest();
