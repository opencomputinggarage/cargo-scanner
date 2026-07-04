import React from "react";
import ReactDOM from "react-dom/client";
import {
  Boxes,
  CheckCircle2,
  Clipboard,
  Code2,
  Container,
  Download,
  FileJson,
  Monitor,
  PackageCheck,
  RefreshCw,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import "./styles.css";

const commands = [
  {
    label: "Fast start",
    value:
      "curl -fsSL https://raw.githubusercontent.com/opencomputinggarage/cargo-scanner/main/scripts/install.sh | sh\ncargo-scanner doctor --fix\ncargo-scanner scan",
  },
  {
    label: "Direct scan",
    value: "cargo-scanner ~/Downloads -R\ncargo-scanner ./artifact.jar -F high",
  },
  {
    label: "Update",
    value: "cargo-scanner update --check\ncargo-scanner update",
  },
  {
    label: "SBOM",
    value: "cargo-scanner sbom ./artifact.jar --sbom-output sbom.cdx.json",
  },
];

const runtimes = [
  ["managed", "Best for personal machines. Cargo Scanner installs Grype, Trivy, and Syft for you."],
  ["docker", "Best for CI and isolated runs with ghcr.io/opencomputinggarage/cargo-scanner-runtime."],
  ["native", "Use existing scanner CLIs already managed on PATH."],
  ["auto", "Prefer local Docker image, then managed tools, then native tools."],
];

const checks = [
  "Install script verifies checksums",
  "Managed tools keep provenance manifests",
  "Self-update verifies release checksums",
  "JSON, SARIF, raw scanner output, and SBOM output",
  "Summary-first result viewer with details on demand",
  "Plain output with NO_COLOR or CARGO_SCANNER_PLAIN",
];

const shoutouts = [
  {
    name: "Grype",
    href: "https://github.com/anchore/grype",
    detail: "Vulnerability scanning from Anchore.",
  },
  {
    name: "Syft",
    href: "https://github.com/anchore/syft",
    detail: "SBOM generation from Anchore.",
  },
  {
    name: "Trivy",
    href: "https://github.com/aquasecurity/trivy",
    detail: "Vulnerability scanning, SBOMs, and security databases from Aqua Security.",
  },
  {
    name: "Charm",
    href: "https://charm.sh/",
    detail: "Bubble Tea, Bubbles, Lip Gloss, Huh, and Glamour power the terminal UX.",
  },
  {
    name: "GoReleaser",
    href: "https://goreleaser.com/",
    detail: "Multi-platform release automation.",
  },
];

function App() {
  const [activeCommand, setActiveCommand] = React.useState(commands[0]);

  async function copy(text: string) {
    await navigator.clipboard.writeText(text);
  }

  return (
    <main>
      <section className="hero">
        <nav>
          <div className="brand">
            <PackageCheck size={24} />
            <span>Cargo Scanner</span>
          </div>
          <div className="nav-actions">
            <a href="https://github.com/opencomputinggarage/cargo-scanner/releases/latest">Releases</a>
            <a href="https://github.com/opencomputinggarage/cargo-scanner">
              <Code2 size={18} />
              GitHub
            </a>
          </div>
        </nav>

        <div className="hero-grid">
          <div className="hero-copy">
            <p className="eyebrow">Inspect inbound artifacts before you unpack or ship them.</p>
            <h1>Cargo Scanner</h1>
            <p className="lede">
              A unified CLI for local vulnerability scans and SBOM generation with Grype, Trivy, and Syft.
              Use managed tools on personal machines, Docker in CI, or native scanner CLIs when your team
              already manages them.
            </p>
            <div className="hero-actions">
              <a className="primary" href="#quickstart">
                <Terminal size={18} />
                Quickstart
              </a>
              <a className="secondary" href="https://github.com/opencomputinggarage/cargo-scanner#troubleshooting">
                Troubleshooting
              </a>
            </div>
          </div>

          <div className="terminal-shot" aria-label="Cargo Scanner terminal preview">
            <div className="terminal-bar">
              <span></span>
              <span></span>
              <span></span>
            </div>
            <pre>{`$ cargo-scanner scan
What should be scanned?
Choose a common target or enter a path.
> Current folder (.)
  Enter another path

Scan recursively?
Recursive scan uses -R / --recursive.
> Yes, scan files inside this folder
  No, folder only

What kind of result do you need?
> Grype - vulnerabilities
  Trivy - vulnerabilities
  Syft - SBOM inventory

$ cargo-scanner
╭────────────────────────────────────────╮
│ Cargo Scanner   workspace safety       │
│ Managed tools 3/3 ready                │
│                                        │
│ > Scan Something                       │
│   Scan Current Folder                  │
│   Fix Setup                            │
╰────────────────────────────────────────╯
`}</pre>
          </div>
        </div>
      </section>

      <section id="quickstart" className="band">
        <div className="section-heading">
          <h2>Start In Three Commands</h2>
          <p>Copy the path that matches how you want to work.</p>
        </div>
        <div className="command-layout">
          <div className="command-tabs">
            {commands.map((command) => (
              <button
                key={command.label}
                className={activeCommand.label === command.label ? "active" : ""}
                onClick={() => setActiveCommand(command)}
              >
                {command.label}
              </button>
            ))}
          </div>
          <div className="code-panel">
            <button className="copy" onClick={() => copy(activeCommand.value)}>
              <Clipboard size={16} />
              Copy
            </button>
            <pre>{activeCommand.value}</pre>
          </div>
        </div>
      </section>

      <section className="content-grid">
        <article>
          <ShieldCheck size={28} />
          <h3>Scan Local Artifacts</h3>
          <p>Scan downloads, build outputs, archives, and extracted folders without switching tools.</p>
          <code>cargo-scanner ./artifact.jar --fail-on high</code>
        </article>
        <article>
          <Boxes size={28} />
          <h3>Generate SBOMs</h3>
          <p>Create CycloneDX SBOM output and normalized operation reports from the same CLI.</p>
          <code>cargo-scanner sbom ./artifact.jar --sbom-output sbom.cdx.json</code>
        </article>
        <article>
          <Monitor size={28} />
          <h3>Use The TUI</h3>
          <p>Start with a scanner-aware conversation, then use direct commands when ready.</p>
          <code>cargo-scanner scan</code>
        </article>
      </section>

      <section className="band split">
        <div>
          <h2>Runtime Strategy</h2>
          <p>
            Cargo Scanner keeps scanner adapters and runtime adapters separate, so the same commands work
            across personal laptops, CI, and machines with existing scanner installations.
          </p>
        </div>
        <div className="runtime-list">
          {runtimes.map(([name, description]) => (
            <div key={name} className="runtime-row">
              <span>{name}</span>
              <p>{description}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="content-grid compact">
        <article>
          <Download size={24} />
          <h3>Managed Tools</h3>
          <p>Install and update Grype, Trivy, and Syft under Cargo Scanner's home directory.</p>
        </article>
        <article>
          <Container size={24} />
          <h3>Docker Runtime</h3>
          <p>Use the GHCR runtime image for isolated execution and CI-friendly behavior.</p>
        </article>
        <article>
          <FileJson size={24} />
          <h3>Automation Output</h3>
          <p>Text opens a summary-first result viewer; JSON and SARIF stay automation-friendly.</p>
        </article>
        <article>
          <RefreshCw size={24} />
          <h3>Self Update</h3>
          <p>Check GitHub Releases, verify checksums, and replace the current executable in place.</p>
        </article>
      </section>

      <section className="band checklist">
        <h2>DX Care Built In</h2>
        <div>
          {checks.map((check) => (
            <p key={check}>
              <CheckCircle2 size={18} />
              {check}
            </p>
          ))}
        </div>
      </section>

      <section className="band shoutouts">
        <div>
          <h2>Open Source Shoutouts</h2>
          <p>
            Cargo Scanner stands on focused open source tools maintained by security,
            terminal UX, and release engineering communities.
          </p>
        </div>
        <div className="shoutout-list">
          {shoutouts.map((item) => (
            <a key={item.name} href={item.href} className="shoutout-row">
              <span>{item.name}</span>
              <p>{item.detail}</p>
            </a>
          ))}
        </div>
      </section>
    </main>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
