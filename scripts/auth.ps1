$RED = "`e[0;31m"
$GREEN = "`e[0;32m"
$YELLOW = "`e[1;33m"
$BLUE = "`e[0;34m"
$NC = "`e[0m" # No Color
$BOLD = "`e[1m"

$SPINNER = @('-', '\', '|', '/')

function Get-Version {
    return "$(git log -1 --format='%h')-dev"
}

function Show-Status {
    param(
        [scriptblock]$ScriptBlock,
        [string]$Message
    )
    
    $originalCursorTop = [Console]::CursorTop
    $i = 0
    $job = Start-Job -ScriptBlock $ScriptBlock

    while ($job.State -eq 'Running') {
        $spinChar = $SPINNER[$i % $SPINNER.Length]
        [Console]::SetCursorPosition(0, $originalCursorTop)
        Write-Host -NoNewline ($BLUE + $spinChar + $NC + " " + $Message + "...")
        Start-Sleep -Milliseconds 200
        $i++
    }

    $result = Receive-Job -Job $job
    Remove-Job -Job $job

    if ($LASTEXITCODE -eq $null -or $LASTEXITCODE -eq 0) {
        Write-Host "`r${GREEN}✓${NC} ${Message}${GREEN} (done)${NC}"
    }
    else {
        Write-Host "`r${RED}×${NC} ${Message}${RED} (failed)${NC}"
        exit 1
    }
}

function Start-CleanCommand {
    Write-Host "`n${BOLD}Cleaning build artifacts...${NC}`n"
    Show-Status -Message "Cleaning previous builds" -ScriptBlock {
        Remove-Item -ErrorAction SilentlyContinue auth-*.exe
    }
    Show-Status -Message "Cleaning up Go dependencies" -ScriptBlock {
        go mod tidy
    }
    Show-Status -Message "Cleaning Go test cache" -ScriptBlock {
        go clean -testcache
    }
}

function Start-BuildCommand {
    Write-Host "`n${BOLD}Building server...${NC}`n"
    
    # Get version
    $VERSION = Get-Version
    Write-Host "${BOLD}Building version:${NC} ${BLUE}${VERSION}${NC}`n"

    Show-Status -Message "Formatting code" -ScriptBlock {
        go fmt ./...
    }

    Show-Status -Message "Building executable" -ScriptBlock {
        $env:VERSION = $VERSION
        go build -ldflags "-X main.version=$VERSION" -o "auth-$VERSION.exe" ./cmd/server/main.go
    }

    Write-Host "`n${GREEN}✓${NC} Build successful: ${BLUE}auth-${VERSION}.exe${NC}"
}

function Start-RunCommand {
    $VERSION = Get-Version
    if (-not (Test-Path "auth-$VERSION.exe")) {
        Write-Host "${YELLOW}Executable not found, building first...${NC}`n"
        Start-BuildCommand
    }

    Write-Host "`n${BOLD}Starting the server...${NC}"
    & ".\auth-$VERSION.exe"
}

function Start-TestCommand {
    Write-Host "`n${BOLD}Running tests...${NC}`n"
    Show-Status -Message "Running tests" -ScriptBlock {
        go test -v ./...
    }
}

function Start-DevCommand {
    Write-Host "`n${BOLD}Starting development setup...${NC}`n"
    Start-CleanCommand
    Start-TestCommand
    Start-BuildCommand
    Start-RunCommand
}

function Show-HelpCommand {
    Write-Host "${BOLD}Usage:${NC}"
    Write-Host "  ${YELLOW}.\scripts\auth${NC} ${GREEN}<command>${NC}"
    Write-Host "`n${BOLD}Available commands:${NC}"
    Write-Host "  ${GREEN}build${NC}    Build the server executable"
    Write-Host "  ${GREEN}run${NC}      Run the server (builds if needed)"
    Write-Host "  ${GREEN}dev${NC}      Clean, build, and run the server"
    Write-Host "  ${GREEN}test${NC}     Run tests"
    Write-Host "  ${GREEN}clean${NC}    Clean build artifacts and dependencies"
    Write-Host "  ${GREEN}help${NC}     Show this help message"
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
        Write-Host "${RED}Error:${NC} Unknown command '$($args[0])'"
        Show-HelpCommand
        exit 1
    }
}