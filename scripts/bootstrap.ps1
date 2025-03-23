# PowerShell script for setting up development environment on Windows
# Equivalent to the provided bash script

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

# Global variables for configuration
$SUPABASE_CONFIG = @{}
$PROJECT_NAME = "utbt-auth-dev"
$APP_URL = "localhost"
$PORT = "8080"
$DISCORD_CLIENT_ID = ""
$DISCORD_CLIENT_SECRET = ""

function Show-Status {
    param(
        [scriptblock]$ScriptBlock,
        [string]$Message
    )
    
    $originalCursorTop = [Console]::CursorTop
    $i = 0
    $currentDir = Get-Location
    
    $jobScriptBlock = {
        param($dir, $cmd)
        Set-Location $dir
        # Convert the string back to scriptblock and execute it
        $executionBlock = [ScriptBlock]::Create($cmd)
        & $executionBlock
    }
    
    $job = Start-Job -ScriptBlock $jobScriptBlock -ArgumentList $currentDir, $ScriptBlock.ToString()

    while ($job.State -eq 'Running') {
        $spinChar = $SPINNER[$i % $SPINNER.Length]
        [Console]::SetCursorPosition(0, $originalCursorTop)
        Write-ColorOutput -Color $BLUE -Message $spinChar
        Write-Host " $Message..." -NoNewline
        Start-Sleep -Milliseconds 200
        $i++
    }

    $result = Receive-Job -Job $job
    Remove-Job -Job $job

    if ($LASTEXITCODE -eq $null -or $LASTEXITCODE -eq 0) {
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
        exit 1
    }
}

function Check-Command {
    param (
        [string]$command
    )
    
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        Write-ColorOutput -Color $RED -Message "Error: "
        Write-Host "$command is not installed"
        return $false
    }
    return $true
}

function Check-DockerRunning {
    try {
        $dockerInfo = docker info 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-ColorOutput -Color $RED -Message "Error: "
            Write-Host "Docker is not running"
            return $false
        }
        return $true
    }
    catch {
        Write-ColorOutput -Color $RED -Message "Error: "
        Write-Host "Docker is not running"
        return $false
    }
}

function Check-SupabaseLogin {
    try {
        $supabaseList = supabase projects list 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-ColorOutput -Color $RED -Message "Error: "
            Write-Host "Not logged in to Supabase"
            return $false
        }
        return $true
    }
    catch {
        Write-ColorOutput -Color $RED -Message "Error: "
        Write-Host "Not logged in to Supabase"
        return $false
    }
}

function Check-GoVersion {
    $requiredVersion = "1.23"
    try {
        $goVersionOutput = go version
        if ($LASTEXITCODE -ne 0) {
            return $false
        }
        
        # Extract version number - assumes format like "go1.23.0 windows/amd64"
        $versionMatch = [regex]::Match($goVersionOutput, 'go(\d+\.\d+)')
        if ($versionMatch.Success) {
            $goVersion = $versionMatch.Groups[1].Value
            
            # Compare versions
            $v1 = [version]$requiredVersion
            $v2 = [version]$goVersion
            
            if ($v2 -lt $v1) {
                Write-ColorOutput -Color $RED -Message "Error: "
                Write-Host "Go version $requiredVersion or higher is required"
                Write-Host "Current version: " -NoNewline
                Write-ColorOutput -Color $YELLOW -Message $goVersion
                Write-Host ""
                return $false
            }
            return $true
        }
        else {
            Write-ColorOutput -Color $RED -Message "Error: "
            Write-Host "Unable to determine Go version"
            return $false
        }
    }
    catch {
        Write-ColorOutput -Color $RED -Message "Error: "
        Write-Host "Go is not installed or version check failed"
        return $false
    }
}

function Install-Templ {
    Write-Host "`nInstalling templ..." -ForegroundColor White -BackgroundColor Black
    
    try {
        $env:GO111MODULE = "on"
        Show-Status -Message "Installing templ" -ScriptBlock {
            go install github.com/a-h/templ/cmd/templ@latest
        }
        Write-ColorOutput -Color $GREEN -Message "$CHECK "
        Write-Host "templ installed successfully - make sure your Go bin is in your PATH"
        return $true
    }
    catch {
        Write-ColorOutput -Color $RED -Message "Error: "
        Write-Host "Failed to install templ: $_"
        return $false
    }
}

function Setup-GoDeps {
    Write-Host "`nSetting up Go dependencies..." -ForegroundColor White -BackgroundColor Black
    
    try {
        Show-Status -Message "Downloading Go dependencies" -ScriptBlock {
            go mod download
        }
        
        Show-Status -Message "Tidying Go dependencies" -ScriptBlock {
            go mod tidy
        }
        
        Write-ColorOutput -Color $GREEN -Message "$CHECK "
        Write-Host "Go dependencies set up successfully"
    }
    catch {
        Write-ColorOutput -Color $RED -Message "Error: "
        Write-Host "Failed to set up Go dependencies: $_"
        exit 1
    }
}

function Collect-ProjectConfig {
    Write-Host "`nProject Configuration" -ForegroundColor White -BackgroundColor Black
    
    Write-ColorOutput -Color $YELLOW -Message "Enter project name (default: utbt-auth-dev): "
    $inputProjectName = Read-Host
    if ($inputProjectName) {
        $script:PROJECT_NAME = $inputProjectName
    }
    
    Write-ColorOutput -Color $YELLOW -Message "Enter APP URL where the auth server will run (default: localhost): "
    $inputAppUrl = Read-Host
    if ($inputAppUrl) {
        $script:APP_URL = $inputAppUrl
    }
    
    Write-ColorOutput -Color $YELLOW -Message "Enter PORT where the auth server will run (default: 8080): "
    $inputPort = Read-Host
    if ($inputPort) {
        $script:PORT = $inputPort
    }
    
    Write-ColorOutput -Color $YELLOW -Message "Enter Discord Client ID (required for Discord OAuth): "
    $inputDiscordClientId = Read-Host
    if (-not $inputDiscordClientId) {
        Write-ColorOutput -Color $RED -Message "Discord Client ID is required. Get it from the Discord Developer Dashboard."
        Write-Host ""
        Write-ColorOutput -Color $BLUE -Message "https://discord.com/developers/applications"
        Write-Host ""
        exit 1
    }
    $script:DISCORD_CLIENT_ID = $inputDiscordClientId
    
    Write-ColorOutput -Color $YELLOW -Message "Enter Discord Client Secret (required for Discord OAuth): "
    $inputDiscordClientSecret = Read-Host
    if (-not $inputDiscordClientSecret) {
        Write-ColorOutput -Color $RED -Message "Discord Client Secret is required. Get it from the Discord Developer Portal."
        Write-Host ""
        Write-ColorOutput -Color $BLUE -Message "https://discord.com/developers/applications"
        Write-Host ""
        exit 1
    }
    $script:DISCORD_CLIENT_SECRET = $inputDiscordClientSecret
    
    Write-ColorOutput -Color $GREEN -Message "$CHECK "
    Write-Host "Project configuration collected"
}

function Setup-SupabaseConfig {
    Write-Host "`nSetting up Supabase configuration..." -ForegroundColor White -BackgroundColor Black
    
    $configDir = "supabase"
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }
    
    $configFile = Join-Path $configDir "config.toml"
    if (Test-Path $configFile) {
        Write-ColorOutput -Color $YELLOW -Message "$configFile already exists. Do you want to overwrite it? (y/n) "
        $overwrite = Read-Host
        if ($overwrite -ne "y") {
            Write-ColorOutput -Color $YELLOW -Message "Keeping existing configuration."
            Write-Host ""
            return
        }
    }

    $exampleConfig = Join-Path $configDir "config.toml.example"
    if (-not (Test-Path $exampleConfig)) {
        Write-ColorOutput -Color $YELLOW -Message "Example config not found. Creating new config from scratch."
        Write-Host ""
        
        $configContent = @"
project_id = "$PROJECT_NAME"

[auth]
site_url = "http://$APP_URL`:$PORT"
additional_redirect_urls = ["http://$APP_URL`:$PORT/callback"]

[auth.external.discord]
client_id = "$DISCORD_CLIENT_ID"
secret = "$DISCORD_CLIENT_SECRET"
"@
        
        Set-Content -Path $configFile -Value $configContent
    }
    else {
        $configContent = Get-Content $exampleConfig -Raw
        
        # Replace project ID
        $configContent = $configContent -replace 'project_id = "utbt-auth-dev"', "project_id = `"$PROJECT_NAME`""
        
        # Replace site URL and redirect URLs
        $configContent = $configContent -replace 'site_url = "[^"]*"', "site_url = `"http://$APP_URL`:$PORT`""
        $configContent = $configContent -replace 'additional_redirect_urls = \[[^\]]*\]', "additional_redirect_urls = [`"http://$APP_URL`:$PORT/callback`"]"
        
        # Replace Discord credentials
        $configContent = $configContent -replace 'client_id = "your-client-id"', "client_id = `"$DISCORD_CLIENT_ID`""
        $configContent = $configContent -replace 'secret = "your-client-secret"', "secret = `"$DISCORD_CLIENT_SECRET`""

        Set-Content -Path $configFile -Value $configContent
    }
    
    Write-ColorOutput -Color $GREEN -Message "$CHECK "
    Write-Host "Created $configFile with your configuration"
}

function Setup-SupabaseEnv {
    Write-Host "`nSetting up Supabase environment..." -ForegroundColor White -BackgroundColor Black
    
    if (-not (Check-Command "supabase")) {
        Write-ColorOutput -Color $RED -Message "Supabase CLI is not installed"
        Write-Host ""
        Write-Host "Please install it by following instructions at: " -NoNewline
        Write-ColorOutput -Color $BLUE -Message "https://supabase.com/docs/guides/cli"
        Write-Host ""
        exit 1
    }

    if (-not (Check-Command "docker")) {
        Write-ColorOutput -Color $RED -Message "Docker is not installed"
        Write-Host ""
        Write-Host "Please install Docker Desktop from: " -NoNewline
        Write-ColorOutput -Color $BLUE -Message "https://www.docker.com/products/docker-desktop"
        Write-Host ""
        exit 1
    }

    if (-not (Check-DockerRunning)) {
        Write-ColorOutput -Color $YELLOW -Message "Please start Docker Desktop and try again"
        Write-Host ""
        exit 1
    }

    Write-Host "Stopping Supabase if running..." -ForegroundColor White -BackgroundColor Black
    Show-Status -Message "Stopping existing Supabase instances" -ScriptBlock {
        supabase stop
    }
    
    Write-Host "Starting Supabase with new configuration..." -ForegroundColor White -BackgroundColor Black
    
    try {
        $supabaseOutput = supabase start 2>&1
        $supabaseOutputStr = $supabaseOutput -join "`n"
        
        # Improved regex patterns to extract only the specific values
        $apiUrlPattern = 'API URL:\s+(http[s]?:\/\/[^\s]+)'
        $anonKeyPattern = 'anon key:\s+([^\s]+)'
        $serviceRoleKeyPattern = 'service_role key:\s+([^\s]+)'
        
        $apiUrlMatch = [regex]::Match($supabaseOutputStr, $apiUrlPattern)
        if ($apiUrlMatch.Success) {
            $SUPABASE_CONFIG['url'] = $apiUrlMatch.Groups[1].Value.Trim()
        }
        
        $anonKeyMatch = [regex]::Match($supabaseOutputStr, $anonKeyPattern)
        if ($anonKeyMatch.Success) {
            $SUPABASE_CONFIG['anon_key'] = $anonKeyMatch.Groups[1].Value.Trim()
        }
        
        $serviceRoleKeyMatch = [regex]::Match($supabaseOutputStr, $serviceRoleKeyPattern)
        if ($serviceRoleKeyMatch.Success) {
            $SUPABASE_CONFIG['service_role_key'] = $serviceRoleKeyMatch.Groups[1].Value.Trim()
        }
        
        Write-ColorOutput -Color $GREEN -Message "$CHECK "
        Write-Host "Supabase started successfully. API URL: $($SUPABASE_CONFIG['url'])"
    }
    catch {
        Write-ColorOutput -Color $RED -Message "Failed to start Supabase"
        Write-Host ""
        Write-Host $_
        exit 1
    }
}

function Create-EnvFile {
    if (Test-Path ".env") {
        Write-ColorOutput -Color $YELLOW -Message ".env file already exists. Do you want to overwrite it? (y/n) "
        $overwrite = Read-Host
        if ($overwrite -ne "y") {
            Write-ColorOutput -Color $YELLOW -Message "Keeping existing .env file."
            Write-Host ""
            return
        }
    }

    Write-Host "`nCreating .env file..." -ForegroundColor White -BackgroundColor Black

    $supabaseUrl = if ($SUPABASE_CONFIG.ContainsKey('url')) { $SUPABASE_CONFIG['url'] } else { "http://localhost:54321" }
    $supabaseServiceRoleKey = if ($SUPABASE_CONFIG.ContainsKey('service_role_key')) { $SUPABASE_CONFIG['service_role_key'] } else { "your_supabase_service_role_key" }

    $envContent = @"
# Server Configuration
PORT=$PORT
APP_URL=http://$APP_URL`:$PORT
ENV=development

# Supabase Configuration
SUPABASE_INSTANCE=$PROJECT_NAME
SUPABASE_URL=$supabaseUrl
SUPABASE_SERVICE_ROLE_KEY=$supabaseServiceRoleKey

# Logging Configuration
LOG_LEVEL=debug
LOG_FILE=logs/app.log
"@

    Set-Content -Path ".env" -Value $envContent
    Write-ColorOutput -Color $GREEN -Message "$CHECK "
    Write-Host "Created .env file with configuration"
}

function Main {
    Write-Host "`nStarting development environment setup...`n" -ForegroundColor White -BackgroundColor Black

    Write-Host "Checking required tools..." -ForegroundColor White -BackgroundColor Black
    
    # Check for Go
    if (-not (Check-Command "go")) {
        Write-ColorOutput -Color $RED -Message "Go is not installed"
        Write-Host ""
        Write-Host "Please install Go from: " -NoNewline
        Write-ColorOutput -Color $BLUE -Message "https://golang.org/doc/install"
        Write-Host ""
        exit 1
    }
    
    # Check Go version
    if (-not (Check-GoVersion)) {
        Write-ColorOutput -Color $RED -Message "Please upgrade your Go installation to at least version 1.23"
        Write-Host ""
        exit 1
    }
    Write-ColorOutput -Color $GREEN -Message "$CHECK "
    Write-Host "Go version check passed"

    # Check for Templ
    if (-not (Check-Command "templ")) {
        Write-ColorOutput -Color $YELLOW -Message "Templ is not installed. Installing now..."
        Write-Host ""
        if (-not (Install-Templ)) {
            exit 1
        }
    }
    else {
        Write-ColorOutput -Color $GREEN -Message "$CHECK "
        Write-Host "Templ is installed"
    }

    # Check for Git
    if (-not (Check-Command "git")) {
        Write-ColorOutput -Color $RED -Message "Git is not installed"
        Write-Host ""
        Write-Host "Please install Git from: " -NoNewline
        Write-ColorOutput -Color $BLUE -Message "https://git-scm.com/downloads"
        Write-Host ""
        exit 1
    }
    Write-ColorOutput -Color $GREEN -Message "$CHECK "
    Write-Host "Git is installed"

    # Check for Docker
    if (-not (Check-Command "docker")) {
        Write-ColorOutput -Color $RED -Message "Docker is not installed"
        Write-Host ""
        Write-Host "Please install Docker Desktop from: " -NoNewline
        Write-ColorOutput -Color $BLUE -Message "https://www.docker.com/products/docker-desktop"
        Write-Host ""
        exit 1
    }
    
    # Check if Docker is running
    if (-not (Check-DockerRunning)) {
        Write-ColorOutput -Color $RED -Message "Docker is not running"
        Write-Host ""
        Write-ColorOutput -Color $YELLOW -Message "Please start Docker Desktop and try again"
        Write-Host ""
        exit 1
    }
    Write-ColorOutput -Color $GREEN -Message "$CHECK "
    Write-Host "Docker is installed and running"

    # Check for Supabase CLI
    if (-not (Check-Command "supabase")) {
        Write-ColorOutput -Color $RED -Message "Supabase CLI is not installed"
        Write-Host ""
        Write-Host "Please install it by following instructions at: " -NoNewline
        Write-ColorOutput -Color $BLUE -Message "https://supabase.com/docs/guides/cli"
        Write-Host ""
        exit 1
    }
    Write-ColorOutput -Color $GREEN -Message "$CHECK "
    Write-Host "Supabase CLI is installed"
    
    # Check Supabase login status
    if (-not (Check-SupabaseLogin)) {
        Write-ColorOutput -Color $YELLOW -Message "Please login to Supabase using:"
        Write-Host ""
        Write-ColorOutput -Color $BLUE -Message "supabase login"
        Write-Host ""
        exit 1
    }
    Write-ColorOutput -Color $GREEN -Message "$CHECK "
    Write-Host "Logged in to Supabase"

    # Collect project configuration
    Collect-ProjectConfig

    # Setup Go dependencies
    Setup-GoDeps

    # Setup Supabase configuration
    Setup-SupabaseConfig

    # Setup Supabase environment
    Setup-SupabaseEnv

    # Create environment file
    Create-EnvFile

    Write-Host "`n" -NoNewline
    Write-ColorOutput -Color $GREEN -Message "$CHECK Configuration complete!"
    Write-Host ""
    Write-Host "`nYou can now run the app with:" -ForegroundColor White -BackgroundColor Black
    Write-ColorOutput -Color $YELLOW -Message ".\scripts\auth dev"
    Write-Host ""
}

# Check for help parameter
if ($args -contains "-help" -or $args -contains "/help" -or $args -contains "-h" -or $args -contains "--help") {
    Write-Host "Usage: .\scripts\bootstrap.ps1 [options]" -ForegroundColor White
    Write-Host ""
    Write-Host "This script sets up the development environment for the auth service."
    Write-Host "It will check for required tools, collect configuration, and set up Supabase."
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -help, /help, -h, --help  Show this help message and exit"
    exit 0
}

# Execute the main function
Main
