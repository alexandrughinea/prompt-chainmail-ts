import { validateLicense } from "../../shared/src/license.js";

export function validateEnterpriseLicense(): boolean {
  const secret =
    process.env.PROMPT_CHAINMAIL_SECRET ||
    "default-secret-change-in-production";

  return validateLicense(
    "PROMPT_CHAINMAIL_ENTERPRISE_LICENSE",
    "enterprise",
    secret
  );
}
