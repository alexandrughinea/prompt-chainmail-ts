# Prompt Chainmail Pro

Commercial license for Prompt Chainmail with unlimited access to all core rivets and professional support.

## Installation

```bash
npm install @prompt-chainmail/pro
```

## License Key Setup

Set your Pro license key as an environment variable:

```bash
export PROMPT_CHAINMAIL_PRO_LICENSE="pro-1234-5678-9abc"
```

## Usage

```typescript
// Import everything from Pro package (includes all core rivets)
import { PromptChainmail, Chainmails } from '@prompt-chainmail/pro';

// Use any combination of rivets without limitations
const chainmail = new PromptChainmail()
  .forge(Chainmails.sqlInjection())
  .forge(Chainmails.xss())
  .forge(Chainmails.promptInjection())
  .forge(Chainmails.pii())
  .forge(Chainmails.toxicity());

const result = await chainmail.process("User input here");
```

## Pro Benefits

- **Unlimited Rivets**: Access to all security rivets without restrictions
- **Commercial License**: Use in production commercial applications
- **Professional Support**: Priority email and chat support
- **SLA**: 99.9% uptime guarantee
- **License Validation**: Automatic license validation on import

## License

Commercial license. Contact sales@prompt-chainmail.com for pricing and licensing.
