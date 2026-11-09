# Privacy and Data Handling

## Overview

Guardian combines local Windows monitoring with optional
user-initiated cloud-assisted analysis.

This document describes the currently documented application behavior.
It is not a substitute for a formal privacy policy or legal assessment.

## Local processing

The application performs supported endpoint monitoring and
screen text recognition locally.

Guardian Vision uses screen capture and OCR functionality
to extract text for local analysis.

Screen capture is user-initiated or operates within the
configured monitoring workflow.

## Cloud analysis

Cloud analysis is optional and user-initiated.

The desktop client sends the following documented information
to the Cloudflare Worker for analysis:

- Authoritative browser URL.
- OCR-extracted page text.
- Local heuristic findings.

The documented workflow does not upload screenshots.

The Worker communicates with the Anthropic API using
a server-side API credential.

## Credentials

The Guardian Cloud access token is stored under:

`%LOCALAPPDATA%\Guardian\cloud-access-token.bin`

The token is protected using Windows DPAPI with
`DataProtectionScope.CurrentUser`.

The Anthropic API key is configured as a Cloudflare Worker secret.

DPAPI protects stored credentials at rest.
It does not make a shared bearer token safe to distribute
inside a public desktop application.

## Local history

The documented history implementation stores analysis metadata,
including URL/domain, timestamps, local and cloud verdicts,
summaries and token usage.

Raw screenshots and raw OCR text are not documented
as being stored in this history.

Local application data is retained separately from
the application installation directory.

## Limitations

- Cloud analysis requires an external service.
- AI-generated assessments may be inaccurate.
- Local heuristic findings may produce false positives
  or false negatives.
- The application does not provide a guarantee of safety.
- Users should avoid submitting sensitive information
  from private pages to external analysis services.

## Development status

Guardian is under active development.

Data handling behavior may change as the application evolves.
Review this document when introducing new telemetry,
cloud integrations or persistence mechanisms.