# UTBT Auth

[![Auth Release](https://img.shields.io/badge/Auth-v0.1.1-blue)](https://github.com/UT-BT/auth/releases/tag/auth-v0.1.1)


Authentication service built with Go, providing Discord-based authentication and role-based access control (RBAC) for the UTBT platform. This service integrates with Supabase for user management and authentication.

## Features

- **Discord Authentication**: Seamless login using Discord OAuth2
- **Role-Based Access Control**: Hierarchical role system with granular permissions
- **Token Management**: Secure JWT token handling with refresh token support
- **Cookie Management**: Secure HTTP-only cookie handling for authentication
- **CORS Support**: Configurable CORS policies for cross-origin requests
- **Structured Logging**: Comprehensive logging using zerolog
- **Environment Configuration**: Flexible environment-based configuration
- **Static File Serving**: Built-in static file server for web assets

## Prerequisites

- Go 1.23 or higher
- [Supabase](https://supabase.com/) account and project
- Discord Developer account and application
- Environment variables configuration (see [Configuration](#configuration))
- Git (for cloning the repository)

> Note: The project includes a bootstrap script that will help verify and set up these prerequisites automatically.

## Configuration

### Supabase Configuration

#### Discord Authentication Setup

You'll need your Discord application's client ID and secret, which you can get from the Discord Developer Portal.

1. In your Supabase project dashboard, navigate to Authentication > Providers
2. Find Discord in the list and enable it
3. Configure the following settings:
   - Client ID: Your Discord application's client ID
   - Client Secret: Your Discord application's client secret
   - Redirect URL: `https://<your-supabase-project>.supabase.co/auth/v1/callback`

#### Supabase Project Settings

1. In your Supabase project dashboard, go to Authentication > URL Configuration
2. Set the following:
   - Site URL: Your application's URL (e.g., `http://localhost:8080` for development)
   - Redirect URLs: Add your application's callback URL
     - Development: `http://localhost:8080/callback`
     - Production: `https://your-domain.com/callback`

#### Disable Email Authentication

1. In your Supabase project dashboard, go to Authentication > Providers
2. Find Email in the list and disable it
3. This ensures users can only authenticate through Discord

### Auth Server Config

Create a `.env` file in the root directory with the following variables:

```env
# Server Configuration
PORT=8080
ENV=development
APP_URL=http://localhost:8080
LOG_DIR=./logs

# Supabase Configuration
SUPABASE_URL=your_supabase_url
SUPABASE_INSTANCE=your_supabase_instance
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key

# Discord Role Configuration
SUPER_USER_DISCORD_ID=your_super_user_discord_id
ADMIN_ROLE_ID=your_admin_role_id
MODERATOR_ROLE_ID=your_moderator_role_id
```

... or use plain environment variables :)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/UT-BT/auth.git
cd auth
```

2. Run the bootstrap script to set up your development environment:

### Windows
```powershell
.\scripts\bootstrap.bat
```

### Unix/Linux/macOS
```bash
./scripts/bootstrap
```

The bootstrap script will:
- Verify Go and Git are installed
- Check Go version compatibility
- Install templ if not present
- Set up Go dependencies
- Create a default `.env` file if it doesn't exist

3. Update the `.env` file with your configuration values (see [Configuration](#configuration) section)

## Building and Running
> Any *.templ file changes/additions require regeneration. 
> This is handled through our CLI, but can also be done manually with templ generate.
### CLI Tools

The project includes cross-platform CLI tools in the `scripts/` directory to simplify development workflows:

### Windows (PowerShell)
```powershell
.\scripts\auth.ps1 <command>
```

### Unix/Linux/macOS
```bash
./scripts/auth <command>
```

### Windows (Batch)
```batch
.\scripts\auth.bat <command>
```

Available commands:
- `build` - Build the server executable with version information
- `run` - Run the server (automatically builds if needed)
- `dev` - Clean, build, and run the server in development mode
- `test` - Run all tests
- `clean` - Clean build artifacts and dependencies
- `help` - Show help message

The CLI tools provide:
- Automatic version tagging based on git commit hash
- Cross-platform support
- Simplified development workflow

## API Endpoints

### Web Routes
- `GET /` - Index page
- `GET /logout` - Logout page
- `GET /discord` - Discord login redirect
- `GET /callback` - Discord OAuth callback

### API Routes
- `POST /api/refresh` - Refresh authentication token
- `GET /api/verify` - Verify current token
- `POST /api/logout` - Logout user
- `POST /api/store-auth` - Store authentication tokens

## Security Features

- HTTP-only cookies for token storage
- Secure cookie settings in production
- CORS protection
- Token refresh mechanism
- Request ID tracking
- Real IP detection
- Structured error handling

## Project Structure

```
.
├── cmd/
│   └── server/          # Application entry point
├── internal/
│   ├── auth/           # Authentication logic
│   ├── config/         # Configuration management
│   ├── handlers/       # HTTP request handlers
│   ├── logger/         # Logging configuration
│   ├── middleware/     # HTTP middleware
│   └── templates/      # HTML templates
├── static/             # Static web assets
├── .env.example        # Example environment variables
├── go.mod              # Go module definition
├── go.sum              # Go module checksums
└── LICENSE            # License information
```

## Dependencies

- [chi](https://github.com/go-chi/chi) - Lightweight HTTP router
- [templ](https://github.com/a-h/templ) - HTML templating
- [zerolog](https://github.com/rs/zerolog) - Zero allocation JSON logger
- [godotenv](https://github.com/joho/godotenv) - Environment variable loader
- [supabase-community/auth-go](https://github.com/supabase-community/auth-go) - Supabase Auth Go client
- [go-chi/cors](https://github.com/go-chi/cors) - CORS middleware

## License

This project is licensed under the terms found in the [LICENSE](LICENSE) file.