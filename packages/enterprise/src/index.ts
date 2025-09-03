/**
 * Prompt Chainmail Enterprise - Commercial License
 * Validates Enterprise license and provides unlimited access to all core rivets
 */

// Re-export everything from core and pro with license validation
export * from '../../../src/index.js';
export * from '../../../src/rivets.js';
export * from '../../pro/src/index.js';

import { validateEnterpriseLicense } from './license.js';

// Validate license on module load
validateEnterpriseLicense();

export { validateEnterpriseLicense };
