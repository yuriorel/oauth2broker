# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

An OAuth 2 / OIDC broker, exposed as a REST API and written in Java.

## Current State

The repository has no code yet, only `LICENSE` and this file. The first step is to write `./docs/PLAN.md` (see Strategy). Once the project is scaffolded, add the build, test, single-test and run commands here, along with a short architecture overview.

## Technical Requirements

- Java 25 SDK (installed locally), with `--enable-preview` (needed for structured concurrency).
- Spring Boot, latest version (Spring Web MVC). Endpoints are hand-written; Spring Authorization Server is not used.
- Build with Maven (Maven Wrapper).
- Standalone authorization server: users sign in through the broker's own login form.
- Tokens: access token is a JWT (RS256), refresh token is opaque. Both are stored in Redis.
- Endpoints: `authorization`, `token`, `revoke`, `userinfo`.
- Implement the authorization code flow now. Also support JWT client assertion (RFC 7523, `private_key_jwt`) for client authentication at the token endpoint.
- Storage: local Redis on the default port 6379, used for client registrations and tokens. Redis is not installed yet. Assume it will be available during development.
- Use self-signed certificates for TLS during testing.
- This project is meant to be a guide to modern Java features. Use each of these where it fits naturally:
  1. Virtual threads for concurrency
  2. Structured concurrency where needed
  3. Records wherever possible
  4. Sealed classes and interfaces
  5. Local variable type inference (`var`)
  6. Switch expressions
  7. Pattern matching for `switch` and `instanceof`
  8. Text blocks
  9. Unnamed patterns and variables (`_`)
  10. Stream API enhancements (e.g. gatherers)
  11. Module import declarations
  12. Scoped values
  13. Flexible constructor bodies

## Strategy

1. Write the plan to `./docs/PLAN.md`, with success criteria to check off for each phase. Include project scaffolding (with `.gitignore`) and rigorous unit testing.
2. Carry out the plan and make sure every criterion is met.
3. Run extensive integration tests (Playwright or similar) and fix the defects they find.
4. The work is done only when the MVP is finished and tested, and the server is running and ready for the user.

## Coding Standards

1. Use the latest library versions and current idiomatic approaches.
2. Keep it simple: never over-engineer, always simplify, and avoid unnecessary defensive programming. Add no extra features.
3. Be concise. Keep the README minimal. Never use emojis.
