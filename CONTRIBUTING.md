# Contributing to UTBT Auth

Thank you for your interest in contributing to the UTBT Auth project! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## Getting Started

### Prerequisites

- Go 1.23 or higher
- [Supabase](https://supabase.com/) account
- Discord Developer account and application
- Git

### Setting Up the Development Environment

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR-USERNAME/auth.git
   cd auth
   ```
3. Run the bootstrap script to set up your development environment:

   **Windows:**
   ```powershell
   .\scripts\bootstrap.bat
   ```

   **Unix/Linux/macOS:**
   ```bash
   ./scripts/bootstrap
   ```

4. Configure the environment variables by copying `.env.example` to `.env` and updating the values.

### Supabase Setup

Follow the instructions in `supabase/README.md` to set up your local Supabase instance:

1. Install [Supabase CLI](https://supabase.com/docs/guides/cli)
2. Install [Docker](https://docs.docker.com/get-docker/)
3. Login to Supabase CLI: `supabase login`
4. Initialize Supabase using the bootstrap script

## Development Workflow

### Branch Naming Convention

- `feature/your-feature-name` for new features
- `bugfix/issue-description` for bug fixes
- `docs/what-you-documented` for documentation updates

### Development Commands

The project includes cross-platform CLI tools in the `scripts/` directory to simplify development workflows:

**Windows (PowerShell):**
```powershell
.\scripts\auth.ps1 <command>
```

**Unix/Linux/macOS:**
```bash
./scripts/auth <command>
```

Available commands include:
- `build`: Builds the server executable.
- `run`: Runs the server (builds first if needed).
- `dev`: Cleans, generates templates, tests, builds, and runs the server.
- `test`: Runs tests.
- `clean`: Cleans build artifacts and dependencies.
- `generate`: Generates HTMX templates.
- `help`: Shows the help message.

## Pull Request Process

1. Update the README.md with details of changes if applicable
2. Make sure all tests pass
3. The PR should work for all supported platforms (Windows, Linux, macOS)
4. Ensure your code follows the project's style guidelines
5. Include a clear description of the changes and their purpose

## Release Process

This project uses GitHub Actions for automated builds and releases. The process is defined in `.github/workflows/build-and-release.yml`.

To create a new release:
1. Go to the Actions tab in the GitHub repository
2. Select the "Build and Release" workflow
3. Click "Run workflow"
4. Enter the version number in the format `1.0.0`
5. The workflow will build the project for multiple platforms and create a new release

## Additional Resources

- [Go Documentation](https://golang.org/doc/)
- [Supabase Documentation](https://supabase.com/docs)
- [Discord API Documentation](https://discord.com/developers/docs)

## Questions or Need Help?

Feel free to open an issue on GitHub if you have any questions or need assistance with your contribution. You can also join us on our [Discord](https://utbt.net/discord).
