# UTBT Auth

[![Auth Release](https://img.shields.io/badge/Auth-latest-blue)](https://github.com/UT-BT/auth/releases/latest)



Authentication service built with Go, providing Discord-based authentication and role-based access control (RBAC) for the UTBT platform. This service integrates with Supabase for user management and authentication.

## Features

- **Discord Authentication**: Login using Discord OAuth2
- **Role-Based Access Control**: Hierarchical role system with granular permissions
- **Token Management**: JWT token handling with refresh token support
- **Cookie Management**: HTTP-only cookie handling for authentication
- **CORS Support**: Configurable CORS policies for cross-origin requests
- **Static File Serving**: Built-in static file server for web assets

Leveraging Supabase and Discord OAuth2, this service allows players to:
1. Login on their browser, maintaining their logged in status throughout all of the *.utbt.net sphere
2. Login on our UT99 game servers, having their registered HWID stored in the DB for player validation
3. Login through our API and access UTBT data

## Prerequisites

- Go 1.23 or higher
- [Supabase](https://supabase.com/) account
- Discord Developer account and application

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

## Building and Running
The project includes cross-platform CLI tools in the `scripts/` directory to simplify development workflows. Use the `help` command to see all available options:

### Windows (PowerShell)
```powershell
.\scripts\auth.ps1 help
```

Available commands include:
- `build`: Builds the server executable.
- `run`: Runs the server (builds first if needed).
- `dev`: Cleans, generates templates, tests, builds, and runs the server.
- `test`: Runs tests.
- `clean`: Cleans build artifacts and dependencies.
- `generate`: Generates HTMX templates.
- `help`: Shows the help message.

### Unix/Linux/macOS
```bash
./scripts/auth help
```
Available commands include:
- `build`: Builds the server executable.
- `run`: Runs the server (builds first if needed).
- `dev`: Cleans, generates templates, tests, builds, and runs the server.
- `test`: Runs tests.
- `clean`: Cleans build artifacts and dependencies.
- `generate`: Generates HTMX templates.
- `help`: Shows the help message.

## Dependencies

- [chi](https://github.com/go-chi/chi) - Lightweight HTTP router
- [templ](https://github.com/a-h/templ) - HTML templating
- [zerolog](https://github.com/rs/zerolog) - Zero allocation JSON logger
- [godotenv](https://github.com/joho/godotenv) - Environment variable loader
- [supabase-community/auth-go](https://github.com/supabase-community/auth-go) - Supabase Auth Go client
- [go-chi/cors](https://github.com/go-chi/cors) - CORS middleware

## CI/CD

This project uses GitHub Actions (`.github/workflows/build-and-release.yml`) to automate the build and release process.

## License

This project is licensed under the terms found in the [LICENSE](LICENSE) file.