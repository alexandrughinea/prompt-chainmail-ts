/**
 * Prompt Chainmail Pro - Commercial License
 * Validates Pro license and provides unlimited access to all core rivets
 */

// Re-export everything from core with license validation
export * from '../../../src/index.js';
export * from '../../../src/rivets.js';

import { validateProLicense } from './license.js';

// Validate license on module load
validateProLicense();

export { validateProLicense };
