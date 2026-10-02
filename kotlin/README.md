# AppMap (Kotlin / JVM)

A Kotlin/JVM port of **AppMap** - the defensive, OSI Layer 7 application-layer
service and metadata discovery tool - built with **Gradle** and the **JDK**.

Same scope and same safety posture as the Python original: given a hostname or
URL you own or are explicitly authorised to test, it gathers publicly exposed
application-layer metadata (DNS records, a normal HTTP/HTTPS response, TLS
certificate details) and renders a relationship graph. It makes only ordinary,
low-rate requests and never performs port scanning, flooding, exploitation,
brute forcing, credential testing, or any attempt to bypass access controls.

## Requirements

- **JDK 21** (tested with Temurin 21.0.12)
- **Gradle 8.10** (a Gradle wrapper is not bundled; use a system Gradle)

## Build

```bash
gradle build            # compiles and runs the unit tests
gradle fatJar           # builds a standalone runnable jar
```

The standalone jar lands in `build/libs/appmap-kotlin-1.0.0-all.jar`.

## Run

```bash
# via Gradle
gradle run --args="example.com"

# via the standalone jar
java -jar build/libs/appmap-kotlin-1.0.0-all.jar example.com
java -jar build/libs/appmap-kotlin-1.0.0-all.jar example.com --json out.json --csv summary.csv
```

Options: `--json PATH`, `--csv PATH`, `--output-dir DIR`, `--timeout SECONDS`,
`--no-http`, `--no-tls`, `--quiet`, `--version`, `--help`.

## Project layout

```
appmap-kotlin/
├── build.gradle.kts        Gradle build (Kotlin JVM + application plugin)
├── settings.gradle.kts     resolves plugins from Maven Central
├── gradle.properties       JVM args + proxy settings
└── src/
    ├── main/kotlin/com/appmap/
    │   ├── Main.kt          CLI, scan pipeline, terminal report
    │   ├── Target.kt        hostname/URL parsing + validation
    │   ├── DnsAnalyzer.kt   A/AAAA/MX/NS/CNAME/TXT via the JDK JNDI DNS provider
    │   ├── HttpAnalyzer.kt  one GET via java.net.http, manual redirect chain
    │   ├── TlsAnalyzer.kt   handshake + certificate metadata via javax.net.ssl
    │   ├── Graph.kt         relationship graph + ASCII tree
    │   ├── Exporter.kt      JSON / CSV export
    │   └── Json.kt          dependency-free JSON writer
    └── test/kotlin/com/appmap/
        ├── TargetTest.kt
        ├── JsonTest.kt
        └── GraphTest.kt
```

## Design notes

- **No third-party runtime dependencies.** DNS uses the JDK's built-in JNDI DNS
  provider; HTTP uses `java.net.http.HttpClient`; TLS uses `javax.net.ssl`. Only
  the Kotlin standard library (bundled in the fat jar) and the test library are
  pulled from Maven Central.
- **Redirects are followed manually** so the full chain can be recorded, and the
  response body is discarded - metadata only.
- **TLS** performs a verified handshake first; if that fails it records what the
  server presented, unverified, purely as metadata.
- The JSON shape mirrors the Python version, with an extra `"runtime":
  "kotlin/jvm"` field.

## Running on a memory-constrained machine

Gradle and the Kotlin compiler are memory-hungry. If you hit
`Could not allocate compressed class space` or a JVM crash, the host has a
virtual-memory (`ulimit -v`) or RAM cap. Raise the soft limit and keep the JVM
modest:

```bash
ulimit -v unlimited
export GRADLE_OPTS="-Xmx512m -XX:MaxMetaspaceSize=384m"
```

## Limitations

- Reports only what a service publicly exposes.
- TLS inspection connects to port 443.
- DNS lookups need outbound DNS access from the machine running AppMap.
