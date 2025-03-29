# ANSI color codes for PowerShell - using a simpler approach
function Write-ColorOutput {
    param (
        [string]$Message,
        [string]$Color = "White"
    )
    
    $originalColor = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $Color
    Write-Host $Message -NoNewline
    $host.UI.RawUI.ForegroundColor = $originalColor
}

# Color constants
$RED = "Red"
$GREEN = "Green"
$YELLOW = "Yellow"
$BLUE = "Cyan"
$CHECK = [char]0x2713 # Checkmark character ✓
$CROSS = [char]0x00D7 # Cross character ×
$SPINNER = @('-', '\', '|', '/')

function Get-Version {
    try {
        $gitVersion = git log -1 --format='%h'
        if ([string]::IsNullOrEmpty($gitVersion)) {
            return "unknown-dev"
        }
        return "$gitVersion-dev"
    } catch {
        return "unknown-dev"
    }
}

function Show-Status {
    param(
        [scriptblock]$ScriptBlock,
        [string]$Message,
        [hashtable]$Parameters = @{}
    )
    
    $originalCursorTop = [Console]::CursorTop
    $i = 0
    $currentDir = Get-Location
    
    $jobScriptBlock = {
        param($dir, $cmd, $params)
        Set-Location $dir
        
        try {
            $executionBlock = [ScriptBlock]::Create($cmd)
            
            $output = $null
            $errorOutput = $null
            
            $output = & $executionBlock @params 2>&1
            $exitCode = $LASTEXITCODE
            
            if ($exitCode -and ($exitCode -ne 0 -or ($output -match "error:|failed|undefined"))) {
                throw "Command failed with exit code $exitCode. Output: $output"
            }
            
            return @{
                Success = $true
                ExitCode = 0
                Output = $output
            }
        }
        catch {
            return @{
                Success = $false
                ExitCode = 1
                Error = $_
                Output = $output
            }
        }
    }
    
    $job = Start-Job -ScriptBlock $jobScriptBlock -ArgumentList $currentDir, $ScriptBlock.ToString(), $Parameters

    while ($job.State -eq 'Running') {
        $spinChar = $SPINNER[$i % $SPINNER.Length]
        [Console]::SetCursorPosition(0, $originalCursorTop)
        Write-ColorOutput -Color $BLUE -Message $spinChar
        Write-Host " $Message..." -NoNewline
        Start-Sleep -Milliseconds 200
        $i++
    }

    $result = Receive-Job -Job $job -Keep
    Remove-Job -Job $job

    if ($result -is [hashtable] -and $result.ContainsKey('Success')) {
        $jobSuccess = $result.Success
    } else {
        $jobSuccess = $false
        $result = @{
            Success = $false
            Error = "Job did not return expected result format"
            Output = $result
        }
    }

    if ($jobSuccess) {
        Write-Host "`r" -NoNewline
        Write-ColorOutput -Color $GREEN -Message "$CHECK "
        Write-Host "$Message" -NoNewline
        Write-ColorOutput -Color $GREEN -Message " (done)"
        Write-Host ""
    }
    else {
        Write-Host "`r" -NoNewline
        Write-ColorOutput -Color $RED -Message "$CROSS "
        Write-Host "$Message" -NoNewline
        Write-ColorOutput -Color $RED -Message " (failed)"
        Write-Host ""
        if ($result.Error) {
            Write-Host "Error: $($result.Error)" -ForegroundColor Red
        }
        if ($result.Output) {
            Write-Host "Output: $($result.Output)" -ForegroundColor Red
        }
        exit 1
    }

    return $result | Out-Null
}

function Start-CleanCommand {
    Write-Host "`nCleaning build artifacts...`n" -ForegroundColor White -BackgroundColor Black
    Show-Status -Message "Cleaning previous builds" -ScriptBlock {
        if (Test-Path -Path "auth-*") {
            Remove-Item -Path "auth-*" -Force
        }
    }
    Show-Status -Message "Cleaning up Go dependencies" -ScriptBlock {
        go mod tidy
        if ($LASTEXITCODE -ne 0) {
            throw "go mod tidy failed with exit code $LASTEXITCODE"
        }
    }
    Show-Status -Message "Cleaning Go test cache" -ScriptBlock {
        go clean -testcache
        if ($LASTEXITCODE -ne 0) {
            throw "go clean failed with exit code $LASTEXITCODE"
        }
    }
}

function Start-BuildCommand {
    Write-Host "`nBuilding server...`n" -ForegroundColor White -BackgroundColor Black

    Show-Status -Message "Generating HTMX templates" -ScriptBlock {
        templ generate
        if ($LASTEXITCODE -ne 0) {
            throw "templ generate failed with exit code $LASTEXITCODE"
        }
    }
    
    $script:VERSION = Get-Version
    Write-Host "Building version: " -NoNewline -ForegroundColor White -BackgroundColor Black
    Write-ColorOutput -Color $BLUE -Message $script:VERSION
    Write-Host "`n"

    Show-Status -Message "Formatting code" -ScriptBlock {
        go fmt ./...
        if ($LASTEXITCODE -ne 0) {
            throw "go fmt failed with exit code $LASTEXITCODE"
        }
    }

    Show-Status -Message "Building executable" -ScriptBlock {
        param($version)
        $env:VERSION = $version
        $buildOutput = go build -ldflags "-X main.version=$version" -o "auth-$version.exe" ./cmd/server/main.go 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "go build failed with exit code $LASTEXITCODE. Output: $buildOutput"
        }
        
        if (-not (Test-Path "auth-$version.exe")) {
            throw "Build completed but executable was not created"
        }
    } -Parameters @{ version = $script:VERSION }

    # Only show success message if we get here (no errors)
    Write-Host "`n" -NoNewline
    Write-ColorOutput -Color $GREEN -Message "$CHECK "
    Write-Host "Build successful: " -NoNewline
    Write-ColorOutput -Color $BLUE -Message "auth-$script:VERSION.exe"
    Write-Host ""
}

function Start-RunCommand {
    $script:VERSION = Get-Version
    $exePath = "auth-$script:VERSION.exe"
    
    if (-not (Test-Path $exePath)) {
        Write-ColorOutput -Color $YELLOW -Message "Executable not found, building first..."
        Write-Host "`n"
        Start-BuildCommand
    }
    
    if (Test-Path $exePath) {
        Write-Host "`nStarting the server..." -ForegroundColor White -BackgroundColor Black
        & "./$exePath"
    } else {
        Write-ColorOutput -Color $RED -Message "Error: "
        Write-Host "Could not find executable $exePath even after building"
        exit 1
    }
}

function Start-TestCommand {
    Write-Host "`nRunning tests...`n" -ForegroundColor White -BackgroundColor Black
    Show-Status -Message "Running tests" -ScriptBlock {
        $testOutput = go test -v ./... 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw "Tests failed with exit code $LASTEXITCODE. Output: $testOutput"
        }
        
        return $testOutput
    }
}

function Start-DevCommand {
    Write-Host "`nStarting development setup...`n" -ForegroundColor White -BackgroundColor Black
    Start-CleanCommand
    Start-TestCommand
    Start-BuildCommand
    Start-RunCommand
}

function Show-HelpCommand {
    Write-Host "Usage:" -ForegroundColor White -BackgroundColor Black
    Write-Host "  " -NoNewline
    Write-ColorOutput -Color $YELLOW -Message ".\scripts\auth"
    Write-Host " " -NoNewline
    Write-ColorOutput -Color $GREEN -Message "<command>"
    Write-Host ""
    
    Write-Host "Available commands:" -ForegroundColor White -BackgroundColor Black
    Write-Host "  " -NoNewline
    Write-ColorOutput -Color $GREEN -Message "build"
    Write-Host "    Build the server executable"
    
    Write-Host "  " -NoNewline
    Write-ColorOutput -Color $GREEN -Message "run"
    Write-Host "      Run the server (builds if needed)"
    
    Write-Host "  " -NoNewline
    Write-ColorOutput -Color $GREEN -Message "dev"
    Write-Host "      Clean, build, and run the server"
    
    Write-Host "  " -NoNewline
    Write-ColorOutput -Color $GREEN -Message "test"
    Write-Host "     Run tests"
    
    Write-Host "  " -NoNewline
    Write-ColorOutput -Color $GREEN -Message "clean"
    Write-Host "    Clean build artifacts and dependencies"
    
    Write-Host "  " -NoNewline
    Write-ColorOutput -Color $GREEN -Message "help"
    Write-Host "     Show this help message"
}

if ($args -contains "-help" -or $args -contains "/help" -or $args -contains "-h" -or $args -contains "--help") {
    Show-HelpCommand
    exit 0
}

switch ($args[0]) {
    "build" {
        Start-BuildCommand
    }
    "run" {
        Start-RunCommand
    }
    "dev" {
        Start-DevCommand
    }
    "test" {
        Start-TestCommand
    }
    "clean" {
        Start-CleanCommand
    }
    "help" {
        Show-HelpCommand
    }
    $null {
        Show-HelpCommand
    }
    default {
        Write-ColorOutput -Color $RED -Message "Error: "
        Write-Host "Unknown command '$($args[0])'"
        Show-HelpCommand
        exit 1
    }
}