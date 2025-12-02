<#
.SYNOPSIS
  Orchestrates common pentest tool containers (nmap, nikto, owasp-zap, sqlmap) and saves results.

.NOTES
  - Requires Docker Desktop to be running and the current user able to run `docker`.
  - ONLY scan hosts/systems you have written authorization to test.
  - This script runs containers that will actively probe the target. Use responsibly.

USAGE
  .\run-scan.ps1 -Target http://example.com
  .\run-scan.ps1 -Target example.com -Tools nmap,nikto -OutDir .\scans
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$Target,

    [string[]]$Tools = @('nmap','nikto','zap','sqlmap'),

    [string]$OutDir = "./scans",

    [switch]$CheckOnly,
    [switch]$AutoConfirm
)

function Abort([string]$msg) {
    Write-Error $msg
    exit 1
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Abort "Docker CLI not found. Install Docker Desktop and make sure `docker` is in PATH."
}

# Confirm authorization
Write-Host "Target: $Target"
Write-Host "Tools: $($Tools -join ',')"
Write-Host "Output directory: $OutDir"
Write-Host ""
Write-Host "WARNING: You must have explicit written authorization to scan the target."
if (-not $CheckOnly) {
    if (-not $AutoConfirm) {
        $authResp = Read-Host "Type 'I HAVE AUTHORIZATION' to continue"
        if ($authResp -ne 'I HAVE AUTHORIZATION') {
            Abort "Authorization not confirmed. Aborting."
        }
    } else {
        Write-Host "AutoConfirm enabled; skipping interactive authorization prompt." -ForegroundColor Yellow
    }
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$absOut = Resolve-Path -Path $OutDir -ErrorAction SilentlyContinue
if (-not $absOut) { New-Item -ItemType Directory -Path $OutDir | Out-Null; $absOut = Resolve-Path -Path $OutDir }
$scanDir = Join-Path $absOut.Path "$timestamp"
New-Item -ItemType Directory -Path $scanDir | Out-Null

Write-Host "Scan output will be saved to: $scanDir" -ForegroundColor Green

# Normalize a hostname for nmap (strip scheme and path)
$nmapTarget = $Target -replace '^https?://','' -replace '^http?://',''
$nmapTarget = $nmapTarget -replace '/.*$',''

# Helper: try pulling a list of docker images and return the first that succeeds
function TryPullImages([string[]]$images) {
    foreach ($img in $images) {
        Write-Host "Attempting to pull image: $img" -ForegroundColor Cyan
        $output = & docker pull $img 2>&1
        $exit = $LASTEXITCODE
        if ($exit -eq 0) {
            Write-Host "Pulled image: $img" -ForegroundColor Green
            return $img
        } else {
            Write-Warning ([string]::Format('Failed to pull {0} (exit {1}). Output: {2}', $img, $exit, ($output -join "`n")))
        }
    }
    return $null
}

foreach ($tool in $Tools) {
    switch ($tool.ToLower()) {
        'nmap' {
            Write-Host "Running Nmap..." -ForegroundColor Cyan
            # Nmap expects hostnames/IPs without scheme
            $dockerArgs = @('run','--rm','-v',"${scanDir}:/output",'instrumentisto/nmap','-A','-T4','-oX','/output/nmap.xml',$nmapTarget)
            Write-Host "docker $($dockerArgs -join ' ')"
            & docker @dockerArgs
        }
        'nikto' {
            Write-Host "Running Nikto..." -ForegroundColor Cyan
            # Try known images; if none available, skip with guidance
            $niktoImage = TryPullImages @('sullo/nikto','jgamblin/nikto','projectdiscovery/nikto')
            if ($niktoImage) {
                $dockerArgs = @('run','--rm','-v',"${scanDir}:/output",$niktoImage,'nikto','-h',$Target,'-o','/output/nikto.txt')
                Write-Host "docker $($dockerArgs -join ' ')"
                & docker @dockerArgs
            } else {
                Write-Warning "No nikto docker images could be pulled. To enable nikto scans, run 'docker login' or install nikto locally and re-run. Skipping nikto."
            }
        }
        'zap' {
            Write-Host "Running OWASP ZAP full scan (baseline)..." -ForegroundColor Cyan
            $zapImage = TryPullImages @('owasp/zap2docker-stable','owasp/zap2docker-weekly')
            if ($zapImage) {
                $dockerArgs = @('run','--rm','-v',"${scanDir}:/zap",$zapImage,'zap-full-scan.py','-t',$Target,'-r','/zap/zap_report.html')
                Write-Host "docker $($dockerArgs -join ' ')"
                & docker @dockerArgs
            } else {
                Write-Warning "No ZAP docker images could be pulled. To enable ZAP scans, run 'docker login' or install ZAP locally. Skipping ZAP."
            }
        }
        'sqlmap' {
            Write-Host "Running sqlmap (non-interactive) - output to sqlmap.txt" -ForegroundColor Cyan
            # Prefer to pull the image first so failures are clearer
            $image = 'sqlmapproject/sqlmap'
            Write-Host "Attempting to pull docker image: $image"
            # Try candidate images first, then fallback to local python clone if necessary
            $sqlImage = TryPullImages @('sqlmapproject/sqlmap','haxpor/sqlmap','mattifestation/sqlmap')
            if ($sqlImage) {
                $dockerArgs = @('run','--rm','-v',"${scanDir}:/output",$sqlImage,'-u',$Target,'--batch','--output-dir=/output')
                $execCmd = "docker $($dockerArgs -join ' ')"
                & cmd /c $execCmd 2>&1 | Tee-Object -FilePath (Join-Path $scanDir 'sqlmap.txt')
            } else {
                Write-Warning "No sqlmap docker images could be pulled. Falling back to local sqlmap if Python is available."
                if (Get-Command python -ErrorAction SilentlyContinue) {
                    $localDir = Join-Path $scanDir 'sqlmap-local'
                    if (-not (Test-Path $localDir)) {
                        Write-Host "Cloning sqlmap repository to $localDir"
                        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git $localDir
                    }
                    Write-Host "Running local sqlmap (this requires Python and network access)"
                    & python (Join-Path $localDir 'sqlmap.py') -u $Target --batch 2>&1 | Tee-Object -FilePath (Join-Path $scanDir 'sqlmap.txt')
                } else {
                    Write-Error "No Python found to run local sqlmap fallback. Install Python or enable Docker access (docker login) and retry."
                }
            }
        }
        default {
            Write-Warning "Tool `$tool` is not supported by this script yet. Skipping."
        }
    }
}

function CheckToolAvailability() {
    Write-Host "Checking tool availability..." -ForegroundColor Cyan
    $summary = @{}

    $dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    $summary.docker = $null -ne $dockerCmd
    if ($summary.docker) {
        Write-Host "Docker CLI available." -ForegroundColor Green
        $candidates = @{
            nmap = @('instrumentisto/nmap')
            nikto = @('sullo/nikto','jgamblin/nikto')
            zap = @('owasp/zap2docker-stable','owasp/zap2docker-weekly')
            sqlmap = @('sqlmapproject/sqlmap','haxpor/sqlmap','mattifestation/sqlmap')
        }

        foreach ($toolKey in $candidates.Keys) {
            $images = $candidates[$toolKey]
            $available = $false
            foreach ($img in $images) {
                Write-Host "Trying pull for $img (this may take time)..." -ForegroundColor Yellow
                $output = & docker pull $img 2>&1
                $exit = $LASTEXITCODE
                if ($exit -eq 0) {
                    Write-Host "Image pull succeeded: $img" -ForegroundColor Green
                    # remove pulled image to avoid local storage growth
                    try { docker image rm $img | Out-Null } catch { }
                    $available = $true
                    break
                } else {
                    Write-Warning "Pull failed for $img (exit $exit). Output: $([string]::Join(' ',($output -join ' ')))"
                }
            }
            $summary[$toolKey] = $available
        }
    } else {
        Write-Warning "Docker CLI not found; checking local tool binaries instead." -ForegroundColor Yellow
        $summary.nmap_local = $null -ne (Get-Command nmap -ErrorAction SilentlyContinue)
        $summary.nikto_local = $null -ne (Get-Command nikto -ErrorAction SilentlyContinue)
        $summary.zap_local = $null -ne (Get-Command zap.sh -ErrorAction SilentlyContinue)
        $summary.python = $null -ne (Get-Command python -ErrorAction SilentlyContinue)
    }

    Write-Host "\nTool availability summary:" -ForegroundColor Cyan
    foreach ($k in $summary.Keys) {
        Write-Host ("{0,-12} : {1}" -f $k, ($summary[$k] -eq $true))
    }

    return $summary
}

if ($CheckOnly) {
    CheckToolAvailability | Out-Null
    exit 0
}

Write-Host "Scan completed. Results: $scanDir" -ForegroundColor Green

Write-Host "Summary of generated files:" -ForegroundColor Yellow
Get-ChildItem -Path $scanDir | ForEach-Object { Write-Host $_.Name }

Write-Host "Reminder: review results, store them securely, and delete any sensitive temporary files when finished." -ForegroundColor Magenta
