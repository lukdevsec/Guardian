# Guardian Architecture

## Overview

Guardian is a Windows security monitoring application composed of
.NET projects, a WinUI 3 desktop client, and an optional Cloudflare Worker.

## Main components

### Guardian.Core

Contains shared detection models and core security logic.

### Guardian.Monitoring

Contains process and network monitoring functionality.

### Guardian.Service

Hosts background service functionality and telemetry communication.

### Guardian.Desktop

Provides the WinUI 3 interface and coordinates application features.

Important areas include:

- Cloud: cloud API client, models and token storage.
- Domain: domain-related functionality.
- Endpoint: endpoint-related functionality.
- History: local analysis history.
- IPC: communication with the monitoring service.
- Notifications: Windows notification integration.
- Vision: screen capture, OCR, browser address extraction and analysis.

### Guardian

An additional Windows application project in the solution.
Its relationship to the other monitoring projects should be
considered when making architectural changes.

## Cloud backend

The Cloudflare Worker is located in `Cloudflare/worker.js`.

It receives user-initiated analysis requests, validates the configured
bearer credential and calls the Anthropic API using a server-side secret.

The Anthropic API key must never be embedded in the desktop application.

## Analysis flow

1. Local monitoring collects supported endpoint events.
2. Guardian Desktop presents endpoint information.
3. Guardian Vision captures selected screen content when requested.
4. OCR extracts text locally.
5. Local heuristics evaluate available indicators.
6. The user may initiate cloud analysis.
7. The Cloudflare Worker forwards the analysis request to Anthropic.
8. A structured assessment is returned to the desktop client.

## Communication and trust boundaries

- Windows processes and network state are external inputs.
- OCR text is untrusted input.
- Browser URL information must be distinguished from OCR-derived text.
- Cloudflare credentials must remain outside source control.
- AI output must be treated as advisory data, not authoritative security enforcement.

## Design principles

- Local-first processing where practical.
- Explicit user initiation of cloud analysis.
- Separation of monitoring, desktop presentation and cloud analysis.
- Secure credential storage.
- Clear distinction between heuristic findings and AI assessments.