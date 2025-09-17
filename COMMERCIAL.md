# Commercial Licensing

## Package Tiers

### Community Edition

- **Package**: `prompt-chainmail`
- **License**: BSL-1.1 (converts to Apache 2.0 in 2029)
- **Usage**: Non-production, internal business use
- **Features**: All security rivets included

### Professional Edition

- **Package**: `@prompt-chainmail/pro`
- **License**: Commercial - $25/month per organization
- **Features**:
  - Unlimited access to all core rivets
  - Commercial license for production use
  - Email support

### Enterprise Edition

- **Package**: `@prompt-chainmail/enterprise`
- **License**: Commercial - $199/month per organization
- **Features**:
  - Everything in Pro
  - Priority support
  - Custom integrations available
  - Volume licensing options

## Usage

### Community Edition

```bash
npm install prompt-chainmail
```

```typescript
import { PromptChainmail, Chainmails } from "prompt-chainmail";
const chainmail = Chainmails.strict();
```

### Professional Edition

```bash
npm install @prompt-chainmail/pro
export PROMPT_CHAINMAIL_PRO_LICENSE="pro-xxxx-xxxx-xxxx"
```

```typescript
import { PromptChainmail, Chainmails } from "@prompt-chainmail/pro";
// ✅ Pro license validated: pro-1234... - Unlimited rivets unlocked
const chainmail = new PromptChainmail().forge(Chainmails.sqlInjection());
```

### Enterprise Edition

```bash
npm install @prompt-chainmail/enterprise
export PROMPT_CHAINMAIL_PRO_LICENSE="pro-xxxx-xxxx-xxxx"
export PROMPT_CHAINMAIL_ENTERPRISE_LICENSE="ent-xxxx-xxxx-xxxx"
```

```typescript
import { PromptChainmail, Chainmails } from "@prompt-chainmail/enterprise";
// ✅ Pro license validated: pro-1234... - Unlimited rivets unlocked
// ✅ Enterprise license validated: ent-5678... - Unlimited rivets unlocked
const chainmail = new PromptChainmail().forge(Chainmails.pii());
```

## Contact

- **Commercial Licensing**: [alexandrughinea.dev+prompt-chainmail+commercial@gmail.com](mailto:alexandrughinea.dev+prompt-chainmail+commercial@gmail.com)
- **General Support**: [alexandrughinea.dev+prompt-chainmail@gmail.com](mailto:alexandrughinea.dev+prompt-chainmail@gmail.com)
