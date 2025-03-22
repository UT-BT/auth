$RED = "`e[0;31m"
$GREEN = "`e[0;32m"
$YELLOW = "`e[1;33m"
$BLUE = "`e[0;34m"
$NC = "`e[0m" # No Color
$BOLD = "`e[1m"

function Test-Command {
    param([string]$Command)
    try {
        Get-Command $Command -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        Write-Host "${RED}Error:${NC} $Command is not installed"
        return $false
    }
}

function Test-GoVersion {
    $requiredVersion = "1.23"
    $goVersion = (go version).Split(" ")[2].TrimStart("go")
    
    if ([version]$goVersion -lt [version]$requiredVersion) {
        Write-Host "${RED}Error:${NC} Go version $requiredVersion or higher is required"
        Write-Host "Current version: ${YELLOW}$goVersion${NC}"
        return $false
    }
    return $true
}

function Install-Templ {
    Write-Host "${BOLD}Installing templ...${NC}"
    go install github.com/a-h/templ/cmd/templ@latest
}

function Set-GoDependencies {
    Write-Host "${BOLD}Setting up Go dependencies...${NC}"
    go mod download
    go mod tidy
}

function New-EnvFile {
    if (-not (Test-Path ".env")) {
        Write-Host "${BOLD}Creating .env file...${NC}"
        @"
# Server Configuration
PORT=8080
ENV=development

# Supabase Configuration
SUPABASE_URL=your_supabase_url
SUPABASE_ANON_KEY=your_supabase_anon_key
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key

# Logging Configuration
LOG_LEVEL=debug
LOG_FILE=logs/app.log
"@ | Out-File -FilePath ".env" -Encoding UTF8
        Write-Host "${YELLOW}Please update the .env file with your actual configuration values${NC}"
    }
}

function Start-Bootstrap {
    Write-Host "${BOLD}Starting development environment setup...${NC}`n"

    # Check for required tools
    Write-Host "${BOLD}Checking required tools...${NC}"
    if (-not (Test-Command "go")) {
        Write-Host "${RED}Please install Go from https://golang.org/doc/install${NC}"
        exit 1
    }

    if (-not (Test-Command "git")) {
        Write-Host "${RED}Please install Git from https://git-scm.com/downloads${NC}"
        exit 1
    }

    # Check Go version
    if (-not (Test-GoVersion)) {
        Write-Host "${RED}Please upgrade your Go installation${NC}"
        exit 1
    }

    # Install templ if not present
    if (-not (Test-Command "templ")) {
        Install-Templ
    }

    # Setup Go dependencies
    Set-GoDependencies

    # Create environment file if needed
    New-EnvFile

    Write-Host "`n${GREEN}✓${NC} Development environment setup complete!"
    Write-Host "`n${BOLD}Next steps:${NC}"
    Write-Host "1. Update the ${YELLOW}.env${NC} file with your configuration"
    Write-Host "2. Run ${YELLOW}.\scripts\auth dev${NC} to start the development server"
}

Start-Bootstrap 