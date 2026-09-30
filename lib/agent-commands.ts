// Install and uninstall commands for each agent platform (roadmap 5.1, 5.2).
// Pure, so the commands the console shows are tested rather than assembled
// inline in a component.

export type AgentPlatform = "linux" | "windows";

// Every file the console's /downloads route will serve.
export const AGENT_DOWNLOADS = [
  "install-agent.sh",
  "uninstall-agent.sh",
  "install-agent.ps1",
  "uninstall-agent.ps1",
  "SHA256SUMS",
  "defendsec-agentd-linux-amd64",
  "defendsec-agentd-linux-arm64",
  "defendsec-agentd-windows-amd64.exe",
  "defendsec-agentd-windows-arm64.exe",
  "defendsec-agent-windows-amd64.msi",
] as const;

export type CommandOptions = {
  host: string;
  downloadBase: string;
  secret: string;
};

// The platform a device reports (Go's runtime.GOOS) as a command family.
export function agentPlatform(platform: string | undefined): AgentPlatform | null {
  switch ((platform ?? "").toLowerCase()) {
    case "linux":
      return "linux";
    case "windows":
      return "windows";
    default:
      return null;
  }
}

function needsCA(downloadBase: string) {
  return downloadBase.startsWith("https://");
}

const CA_PATH = "/tmp/defendsec-console.crt";
const CA_PATH_WIN = "$env:TEMP\\defendsec-console.crt";

// PowerShell single-quoted string: the only escape is a doubled quote.
function psQuote(s: string) {
  return `'${s.replace(/'/g, "''")}'`;
}

function curlFetch(base: string, name: string, dest: string) {
  const ca = needsCA(base) ? `--cacert ${CA_PATH} ` : "";
  return `curl -fL --progress-bar ${ca}"${base}/${name}" -o ${dest}`;
}

export function installCommand(platform: AgentPlatform, o: CommandOptions): string {
  const ca = needsCA(o.downloadBase);
  switch (platform) {
    case "linux":
      return [
        `${curlFetch(o.downloadBase, "install-agent.sh", "/tmp/install-agent.sh")} && \\`,
        `  sudo bash /tmp/install-agent.sh \\`,
        `  --server-http https://${o.host}:47262 \\`,
        `  --server-grpc ${o.host}:47263 \\`,
        `  --tls-server-name ${o.host} \\`,
        `  --enroll-secret ${o.secret} \\`,
        ca ? `  --download-ca ${CA_PATH} \\` : null,
        `  --download-base "${o.downloadBase}"`,
      ]
        .filter((l): l is string => l !== null)
        .join("\n");
    case "windows":
      // Windows PowerShell 5.1 (powershell.exe), elevated. The console's
      // certificate is pinned for this session only, by thumbprint, rather
      // than added to the machine's trusted roots.
      return [
        `# Windows PowerShell, run as administrator.`,
        ...(ca
          ? [
              `# First copy console.crt from the server to ${CA_PATH_WIN}.`,
              `$ca = New-Object Security.Cryptography.X509Certificates.X509Certificate2("${CA_PATH_WIN}")`,
              `[Net.ServicePointManager]::ServerCertificateValidationCallback = { param($a, $c, $h, $e) $e -eq 'None' -or $c.GetCertHashString() -eq $ca.Thumbprint }`,
            ]
          : []),
        `$s = Join-Path $env:TEMP 'install-agent.ps1'`,
        `Invoke-WebRequest -UseBasicParsing ${psQuote(`${o.downloadBase}/install-agent.ps1`)} -OutFile $s`,
        `powershell -ExecutionPolicy Bypass -File $s \``,
        `  -ServerHttp ${psQuote(`https://${o.host}:47262`)} -ServerGrpc ${psQuote(`${o.host}:47263`)} \``,
        `  -TlsServerName ${psQuote(o.host)} -EnrollSecret ${psQuote(o.secret)} \``,
        ca
          ? `  -DownloadBase ${psQuote(o.downloadBase)} -DownloadCa ${CA_PATH_WIN}`
          : `  -DownloadBase ${psQuote(o.downloadBase)}`,
      ]
        .filter((l): l is string => l !== null)
        .join("\n");
  }
}

// The MSI's silent install, for fleet tools (Intune, SCCM, GPO).
export function msiCommand(o: CommandOptions): string {
  return [
    `msiexec /i defendsec-agent-windows-amd64.msi /qn ^`,
    `  SERVER_HTTP=https://${o.host}:47262 SERVER_GRPC=${o.host}:47263 ^`,
    `  TLS_SERVER_NAME=${o.host} ENROLL_SECRET=${o.secret}`,
  ].join("\n");
}

// Uninstall. The installed agent carries its own uninstaller on Windows; the command falls back to downloading it so it works on a host
// installed by hand too.
export function uninstallCommand(
  platform: AgentPlatform,
  downloadBase: string,
  purge: boolean,
): string {
  switch (platform) {
    case "linux":
      return [
        `${curlFetch(downloadBase, "uninstall-agent.sh", "/tmp/uninstall-agent.sh")} && \\`,
        `  sudo bash /tmp/uninstall-agent.sh${purge ? " --purge-data" : ""}`,
      ].join("\n");
    case "windows":
      return [
        `# Windows PowerShell, run as administrator.`,
        `$u = Join-Path $env:ProgramFiles 'DefendSec\\uninstall-agent.ps1'`,
        `if (-not (Test-Path $u)) {`,
        ...(needsCA(downloadBase)
          ? [
              `  $ca = New-Object Security.Cryptography.X509Certificates.X509Certificate2("${CA_PATH_WIN}")`,
              `  [Net.ServicePointManager]::ServerCertificateValidationCallback = { param($a, $c, $h, $e) $e -eq 'None' -or $c.GetCertHashString() -eq $ca.Thumbprint }`,
            ]
          : []),
        `  $u = Join-Path $env:TEMP 'uninstall-agent.ps1'`,
        `  Invoke-WebRequest -UseBasicParsing ${psQuote(`${downloadBase}/uninstall-agent.ps1`)} -OutFile $u`,
        `}`,
        `powershell -ExecutionPolicy Bypass -File $u${purge ? " -PurgeData" : ""}`,
      ].join("\n");
  }
}

// downloadBaseFor derives the console's /downloads URL from its public URL.
export function downloadBaseFor(serverUrl: string): { host: string; downloadBase: string } {
  try {
    const u = new URL(serverUrl);
    return { host: u.hostname || "127.0.0.1", downloadBase: `${u.protocol}//${u.host}/downloads` };
  } catch {
    return { host: "127.0.0.1", downloadBase: "https://127.0.0.1:47261/downloads" };
  }
}
