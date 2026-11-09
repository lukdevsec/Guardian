# Third-Party Notices

Guardian uses third-party software. The MIT license in the repository
applies to Guardian-authored code only. It does not replace or override
the licenses or terms applicable to third-party components.

The dependency list below reflects the versions identified during
the November 2026 repository audit. It is not yet a complete legal
inventory of every transitive dependency or redistributed binary.

## Identified dependencies

| Component | Version | Identified license / terms |
|---|---:|---|
| RapidOcrNet | 4.2.0 | Apache-2.0, as declared in NuGet metadata |
| FlaUI.UIA3 | 5.0.0 | MIT |
| WinUIEx | 2.9.3 | MIT |
| SkiaSharp | 3.119.1 | MIT |
| Microsoft.ML.OnnxRuntime | 1.29.0 | MIT; see upstream third-party notices |
| System.Management | 10.0.14 | MIT |
| Microsoft.WindowsAppSDK | 2.6.5 | Microsoft Software License Terms |
| Microsoft.Graphics.Win2D | 1.4.0 | Microsoft EULA referenced by NuGet metadata |

## Additional notices

- ONNX Runtime includes third-party components. Consult the
  upstream ThirdPartyNotices.txt distributed with the package.
- Windows App SDK includes third-party materials. Consult its
  LICENSE and NOTICE files and applicable Microsoft terms.
- RapidOcrNet packages OCR model files. The package metadata declares
  Apache-2.0; verify the notices and licensing of the exact model
  artifacts before redistributing them separately.
- The Win2D 1.4.0 package references a Microsoft EULA. Its exact
  redistribution conditions have not yet been independently reviewed.

## Distribution

This file is an initial inventory, not a substitute for the complete
license texts and notices required when redistributing third-party
binaries or assets.

Before publishing application installers, review the exact dependency
closure, model artifacts, bundled runtime files, applicable license
terms, and required notices.