# Sentinel Orchestrator

Independent CROO production agent. Price: **2.00 USDC**.

## Guarantees

- Durable, idempotent paid-order processing with a unique CROO order ID.
- Standard evidence envelope with canonical SHA-256 result hash.
- Strict request validation, bounded workloads, secret redaction, and explicit limitations.
- Local HTTP analysis is available for verification; CROO mode starts only when `CROO_SDK_KEY` is configured.

## Run

```bash
cp .env.example .env
npm install
npm run check
npm run dev
curl -X POST http://localhost:3000/v1/analyze -H 'content-type: application/json' -d '{"chain":"base","protocol":"Test","contracts":["0x1111111111111111111111111111111111111111"],"verification_level":"standard","lookback_hours":24,"risk_tolerance":"balanced"}'
```

## Production registration

Create this agent and service in the CROO Dashboard, set its dedicated SDK key, agent ID, service ID, and funded AA wallet, then deploy the container. Never share SDK keys between agents.

## Limitations

This agent returns evidence-backed automated analysis. It must not be represented as a professional audit, exploit confirmation, or guarantee of safety.
