# Prompt Chainmail (beta)

<div align="center">
  <img src="src/logo.png" alt="Prompt Chainmail Logo" width="200" height="200">
</div>

**Security middleware for AI prompt protection**

Composable defense framework protecting your AI prompts from prompt injection, role confusion, and encoded attacks with enterprise monitoring.

[![CI/CD Pipeline](https://github.com/alexandrughinea/prompt-chainmail/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/alexandrughinea/prompt-chainmail/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/prompt-chainmail.svg)](https://badge.fury.io/js/prompt-chainmail)
[![TypeScript](https://img.shields.io/badge/%3C%2F%3E-TypeScript-%230074c1.svg)](http://www.typescriptlang.org/)
[![Security Audit](https://img.shields.io/badge/security-audited-green.svg)](https://github.com/alexandrughinea/prompt-chainmail/actions/workflows/security.yml)
[![License: BSL-1.1](https://img.shields.io/badge/License-BSL--1.1-blue.svg)](https://github.com/alexandrughinea/prompt-chainmail/blob/main/LICENSE)
[![Commercial License](https://img.shields.io/badge/Commercial-Available-success.svg)](mailto:alexandrughinea.dev+prompt-chainmail@gmail.com)
[![Enterprise Ready](https://img.shields.io/badge/Enterprise-Ready-purple.svg)](https://github.com/alexandrughinea/prompt-chainmail#enterprise-edition)

## Features

- **Security** - Composable rivet system (dedicated security plugins) for enterprise-scale deployments
- **Zero Dependencies** - Minimal attack surface with no external dependencies
- **TypeScript** - Full type safety, IntelliSense support, and strict mode compliance
- **Compliance Ready** - Built-in audit logging and security event tracking for SOC2/ISO27001
- **Monitoring Integration** - Native support for Datadog, New Relic, Sentry, and custom telemetry

## Quick Start

```bash
npm install prompt-chainmail
```

### Basic Usage
```typescript
import { Chainmails } from 'prompt-chainmail';

const chainmail = Chainmails.strict();
const result = await chainmail.protect(userInput);

if (!result.success) {
  console.log('Security violation:', result.context.flags);
} else {
  console.log('Safe input:', result.context.sanitized);
}
```

### Custom Protection
```typescript
import { PromptChainmail, Rivets } from 'prompt-chainmail';

const chainmail = new PromptChainmail()
  .forge(Rivets.sanitize())
  .forge(Rivets.patternDetection())
  .forge(Rivets.confidenceFilter(0.8));

const result = await chainmail.protect(userInput);
```

### Production Monitoring
```typescript
import { Chainmails, Rivets, createSentryProvider } from 'prompt-chainmail';
import * as Sentry from '@sentry/node';

Sentry.init({ dsn: 'your-dsn' });

const chainmail = Chainmails.strict()
  .forge(Rivets.telemetry({
    provider: createSentryProvider(Sentry)
  }));
```

### Conditional Assembly
```typescript
import { PromptChainmail, Rivets } from 'prompt-chainmail';

const chainmail = new PromptChainmail();

if (needsBasicProtection) {
  chainmail.forge(Rivets.sanitize());
}

if (detectInjections) {
  chainmail.forge(Rivets.patternDetection());
}

// Custom business logic
chainmail.forge(Rivets.condition(
  (ctx) => ctx.sanitized.includes('sensitive_keyword'),
  'sensitive_content',
  0.3
));

const result = await chainmail.protect(userInput);
```

## LLM Integration

```typescript
import OpenAI from 'openai';
import { Chainmails } from 'prompt-chainmail';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const chainmail = Chainmails.strict();

async function secureChat(userMessage: string) {
  const result = await chainmail.protect(userMessage);
  
  if (!result.success) {
    throw new Error(`Security violation: ${result.context.flags.join(', ')}`);
  }

  return await openai.chat.completions.create({
    model: "gpt-4",
    messages: [
      { role: "system", content: "You are a helpful assistant." },
      { role: "user", content: result.context.sanitized }
    ]
  });
}
```

## Available Rivets

- `Rivets.sanitize()` - HTML removal, whitespace normalization
- `Rivets.patternDetection()` - Common injection patterns
- `Rivets.roleConfusion()` - Role manipulation detection
- `Rivets.encodingDetection()` - Base64/hex/binary/octal/ROT13/URL encoding detection
- `Rivets.structureAnalysis()` - Input structure anomaly detection
- `Rivets.codeInjection()` - Code execution attempts
- `Rivets.sqlInjection()` - SQL injection patterns
- `Rivets.delimiterConfusion()` - Context-breaking attempts
- `Rivets.instructionHijacking()` - Instruction override detection
- `Rivets.templateInjection()` - Template syntax injection detection
- `Rivets.confidenceFilter()` - Block low-confidence input
- `Rivets.rateLimit()` - Request rate limiting
- `Rivets.untrustedWrapper()` - Wrap content in security boundary tags
- `Rivets.httpFetch()` - External HTTP API calls with automatic (configurable) signal abort
- `Rivets.condition()` - Custom logic with predicates
- `Rivets.logger()` - Request logging and debugging
- `Rivets.telemetry()` - Monitoring integration

## Security Context

```typescript
const result = await chainmail.protect(userInput);

console.log({
  flags: result.context.flags,           // Security flags detected
  confidence: result.context.confidence, // Confidence score (0-1)
  blocked: result.context.blocked,       // Whether input was blocked
  sanitized: result.context.sanitized    // Cleaned input
});
```

## Telemetry

### Provider Integration
```typescript
// Sentry
import * as Sentry from '@sentry/node';
import { createSentryProvider } from 'prompt-chainmail';

Sentry.init({ dsn: 'your-dsn' });
chainmail.forge(Rivets.telemetry({
  provider: createSentryProvider(Sentry)
}));

// Datadog
import tracer from 'dd-trace';
import { createDatadogProvider } from 'prompt-chainmail';

tracer.init({
  service: 'prompt-chainmail',
  env: 'production'
});

chainmail.forge(Rivets.telemetry({
  provider: createDatadogProvider(tracer, console)
}));

// New Relic
import newrelic from 'newrelic';
import { createNewRelicProvider } from 'prompt-chainmail';

chainmail.forge(Rivets.telemetry({
  provider: createNewRelicProvider(newrelic)
}));

// Custom Provider
import { TelemetryProvider } from 'prompt-chainmail';

const customProvider: TelemetryProvider = {
  recordEvent: (event, context) => {
    // Send to your custom monitoring system
    fetch('/api/security-events', {
      method: 'POST',
      body: JSON.stringify({ event, context, timestamp: Date.now() })
    });
  },
  recordMetric: (name, value, tags) => {
    // Send metrics to your system
    console.log(`Metric: ${name} = ${value}`, tags);
  }
};

chainmail.forge(Rivets.telemetry({
  provider: customProvider
}));
```



## License

Business Source License 1.1 - Free for non-production use, converts to Apache 2.0 on January 1, 2029.

For commercial licensing: [Contact](mailto:alexandrughinea.dev+prompt-chainmail@gmail.com)
