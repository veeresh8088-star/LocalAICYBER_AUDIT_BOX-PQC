# Project Engineering Rules

## Core rule
Never guess. Inspect the existing codebase before implementing.

## Architecture
- Reuse existing services, utilities, API clients and patterns.
- Do not introduce duplicate implementations.
- Do not modify unrelated files.
- Preserve backward compatibility unless explicitly instructed otherwise.

## APIs
- Never invent API endpoints.
- Never assume HTTP methods.
- Inspect existing API clients, route definitions, OpenAPI specs, environment configuration, documentation and tests.
- Verify endpoint, method, authentication, request schema and response schema before implementation.
- Never hardcode secrets or environment-specific URLs.

## Database
- Inspect existing models and migrations before changing schemas.
- Never silently change existing data contracts.
- Create migrations when required.
- Test both existing and new database behavior.

## Frontend
- Reuse existing components and design system.
- Do not create duplicate components when an existing component can be reused.
- Verify loading, error, empty and success states.

## Backend
- Validate inputs.
- Preserve existing response contracts.
- Handle errors explicitly.
- Add/update tests for changed behavior.

## Implementation workflow
1. Explore
2. Plan
3. Implement
4. Test
5. Debug
6. Re-test
7. Final verification

## Verification
A task is NOT complete until:
- tests pass
- lint/type checking passes
- build passes where applicable
- relevant API endpoints are verified
- no unrelated functionality is broken

Never report "completed successfully" without actual verification.

If something cannot be verified, explicitly report:
`NOT VERIFIED: <reason>`
