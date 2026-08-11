import { execFileSync } from "node:child_process";

export interface WindowsIdentityProof {
  sid: string;
  isAdministrator: boolean;
}

const IDENTITY_PROBE = `
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$adminSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$members = @(Get-LocalGroupMember -SID $adminSid | ForEach-Object { $_.SID.Value })
[pscustomobject]@{
  sid = $sid
  isAdministrator = [bool]($members -contains $sid)
} | ConvertTo-Json -Compress
`.trim();

export function getCurrentWindowsIdentityProof(): WindowsIdentityProof {
  if (process.platform !== "win32") {
    throw new Error("The MT5 trading laboratory requires Windows");
  }
  let parsed: unknown;
  try {
    const output = execFileSync(
      "powershell.exe",
      ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", IDENTITY_PROBE],
      {
        encoding: "utf-8",
        timeout: 15_000,
        maxBuffer: 64 * 1024,
        windowsHide: true,
      },
    );
    parsed = JSON.parse(output);
  } catch {
    throw new Error("Windows runtime identity verification failed closed");
  }
  if (!parsed || typeof parsed !== "object") {
    throw new Error("Windows runtime identity proof is invalid");
  }
  const value = parsed as Record<string, unknown>;
  if (
    Object.keys(value).sort().join(",") !== "isAdministrator,sid" ||
    typeof value.sid !== "string" ||
    !/^S-\d(-\d+)+$/.test(value.sid) ||
    typeof value.isAdministrator !== "boolean"
  ) {
    throw new Error("Windows runtime identity proof schema is invalid");
  }
  return { sid: value.sid, isAdministrator: value.isAdministrator };
}
