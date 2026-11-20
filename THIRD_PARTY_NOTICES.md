# Third-party provenance and notices

GoreeCloud first-party source is MIT. Third-party components are consumed as system tools or pinned package dependencies and are **not** relicensed or copied into this repository. A release must ship required upstream notices for every resolved binary/transitive dependency.

| Dependency | Purpose and pinned interface | Rights / license consideration |
| --- | --- | --- |
| WireGuard and wireguard-tools | Linux kernel tunnel; system wg/wg-quick | Linux kernel and tools GPL-2.0; system software, not vendored; https://www.wireguard.com/ |
| WireGuard Android | Maven com.wireguard.android:tunnel:1.0.20260102 GoBackend | Apache-2.0 wrapper; review bundled native artifacts/attributions; https://git.zx2c4.com/wireguard-android |
| Qt 6.12 Quick | Native Linux QML | LGPL-3.0/GPL/commercial licensing differs by distribution/module; https://www.qt.io/ |
| Next.js 16.4.6, React 19.2.0 | Web UI | MIT, transitive licenses require full review |
| Kotlin, AndroidX Compose and Material 3 | Native Android UI | Apache-2.0 and resolved transitive license review |
| Python stdlib | Local backend | PSF license; no third-party backend runtime dependency |
| GoreeCloud UI | Token reference | Source of brand alpha tokens; MIT; https://github.com/GoreeCloud/gc-ui |

No NetBird or Twingate source has been copied, nor have third-party source files been modified or relicensed. NetBird management components have AGPL-3.0 obligations if later adopted; review AGPL compatibility and network distribution requirements *before* incorporation.

Release gate: resolve full dependency graph, audit and generate SBOM/license reports, reproduce builds, retain license files and publish binary notices.
