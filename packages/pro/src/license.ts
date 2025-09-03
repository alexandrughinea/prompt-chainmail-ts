import { validateLicense } from '../../shared/src/license.js';

/**
 * Validate Pro license JWT with signature verification
 */
export function validateProLicense(): boolean {
  const secret = process.env.PROMPT_CHAINMAIL_SECRET || 'default-secret-change-in-production';
  
  return validateLicense(
    'PROMPT_CHAINMAIL_PRO_LICENSE',
    'pro',
    secret
  );
}
