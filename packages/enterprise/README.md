# Prompt Chainmail Enterprise

Enterprise-grade commercial license with unlimited access to all core rivets, advanced compliance features, SLA, and dedicated support.

## Installation

```bash
npm install @prompt-chainmail/enterprise
```

## License Key Setup

Set both Pro and Enterprise license keys as environment variables:

```bash
export PROMPT_CHAINMAIL_PRO_LICENSE="pro-1234-5678-9abc"
export PROMPT_CHAINMAIL_ENTERPRISE_LICENSE="ent-1234-5678-9abc"
```

## Usage

```typescript
// Import everything from Enterprise package (includes all core and pro rivets)
import { PromptChainmail, Chainmails } from "@prompt-chainmail/enterprise";

// Use any combination of rivets without limitations
const chainmail = new PromptChainmail()
  .forge(Chainmails.sqlInjection())
  .forge(Chainmails.xss())
  .forge(Chainmails.promptInjection())
  .forge(Chainmails.pii())
  .forge(Chainmails.toxicity())
  .forge(Chainmails.profanity())
  .forge(Chainmails.secrets());

const result = await chainmail.process("Enterprise input here");
```

## Enterprise Benefits

- **Unlimited Rivets**: Access to all security rivets without restrictions
- **Commercial License**: Use in production commercial applications
- **Enterprise SLA**: 99.99% uptime guarantee with custom agreements
- **Dedicated Support**: 24/7 phone and email support
- **On-premise Deployment**: Available for air-gapped environments
- **Custom Integrations**: Tailored solutions for enterprise needs
- **License Validation**: Automatic license validation on import

## Compliance Ready

- **HIPAA**: Healthcare data protection
- **SOX**: Financial reporting compliance
- **PCI DSS**: Payment card industry standards
- **ISO 27001**: Information security management
- **GDPR**: European data protection regulation
- **SOC2**: Service organization controls

## License

Enterprise commercial license. Contact [alexandrughinea.dev+prompt-chainmail+commercial@gmail.com](mailto:alexandrughinea.dev+prompt-chainmail+commercial@gmail.com) for pricing and custom agreements.
