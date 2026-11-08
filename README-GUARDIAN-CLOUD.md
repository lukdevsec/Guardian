# Guardian v0.9.2 — Premium UI + Claude Cloud

This private developer build reorganizes the desktop UI and adds a server-side official-domain context signal to the Claude assessment.

## UI changes

- Dashboard is now an endpoint overview only: process events, TCP events, alert count, monitoring state and latest event.
- Endpoint has a dedicated searchable process inventory and established TCP connection snapshot, with manual refresh.
- Guardian Vision has its own page for manual capture, continuous capture, local heuristics and user-triggered Claude analysis.
- Security Alerts combines endpoint `alerts.jsonl` entries with HIGH/CRITICAL local and Cloud Vision findings.
- History shows locally persisted Vision/Claude report metadata.
- Settings contains Windows notification testing and privacy/cloud notes.

## Cloud AI and domain context

Deploy `Cloudflare/worker.js` to the existing `guardian-cloud-api` Worker. It reports version `0.4.0` from `/health`.

Required Cloudflare **Secret** bindings remain:

- `ANTHROPIC_API_KEY`
- `GUARDIAN_ACCESS_TOKEN`

The Worker includes a small official-domain registry. It uses hostname-boundary matching and returns `analysis.domainAssessment` separately from Claude's confidence score. A registry match is a positive consistency signal only; it is not a reputation check or a guarantee of safety. Absence from the small registry is not evidence of phishing.

**Do not force AI confidence to 100%.** Confidence is the model's certainty in its assessment, not the probability that a site is safe. The report now shows official-domain registry status separately so a known domain match is visible without falsifying model confidence.

## One-time token setup on the developer PC

The app reads a Windows DPAPI-encrypted token from:

`%LOCALAPPDATA%\Guardian\cloud-access-token.bin`

From the project root:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Scripts\Setup-GuardianCloudToken.ps1
```

Paste the existing `GUARDIAN_ACCESS_TOKEN` from Cloudflare when prompted. Do not paste the token into source code, GitHub or this chat.

## Build and run

1. Back up/commit your current working project.
2. Extract this archive into a new folder; do not overwrite the working project yet.
3. Deploy `Cloudflare/worker.js` to the existing Worker and verify `/health` returns `version: 0.4.0`.
4. Open `Guardian.slnx` in Visual Studio.
5. Right-click the solution and choose **Restore NuGet Packages** (or allow Visual Studio to restore during build).
6. Set `Guardian.Desktop` as the Startup Project.
7. Select `Debug` and `x64`.
8. Run **Build → Rebuild Solution**.
9. Run with F5.
10. Run the token setup script once if this Windows account has not provisioned the token.

## Validation and limitations

The XAML files and project XML were checked for well-formedness, and XAML event-handler names were cross-checked against code-behind. This environment does not have the Windows SDK/.NET SDK required to compile WinUI 3, so the final build must be verified in Visual Studio on Windows.

- Endpoint process inventory is a best-effort snapshot. Windows may deny access to protected process metadata.
- TCP view is established IPv4 connections returned by Windows IP Helper API; it is not packet inspection.
- Continuous Vision still uses selected-window capture. It does not silently capture every monitor.
- Cloud AI is user-initiated. The client sends the verified browser URL, OCR text and local heuristic findings; it does not upload screenshots.
- History stores URL/domain, timestamps, local/cloud verdicts, summaries and token usage, but not raw OCR or screenshots.
- Claude is advisory. It does not block processes or websites.
- The shared bearer token is for a private developer build only. DPAPI protects it at rest for the current Windows user, but a shared token embedded in a distributed EXE can be extracted. Do not distribute this build to other users until per-user/device enrollment, revocation and server-side quotas/rate limits are implemented.
