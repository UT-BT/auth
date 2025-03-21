# UTBT Auth

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

## Configuration

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

2. Install dependencies:
```bash
go mod download
```

3. Set up your environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration values
```

## Building and Running

### Development Mode
```bash
go run cmd/server/main.go
```

### Production Build
```bash
go build -o auth cmd/server/main.go
./auth
```

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