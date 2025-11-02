#!/usr/bin/env node

/**
 * Armorly - Test Runner
 * 
 * Runs all security component tests in Node.js environment
 */

console.log('🛡️  Armorly Security Components Test Suite');
console.log('='.repeat(60));
console.log('Starting tests...\n');

// Import and run tests
import('./security-components.test.js')
  .then(() => {
    console.log('\n✅ All tests completed!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n❌ Test suite failed:', error);
    process.exit(1);
  });

