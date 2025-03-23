# Supabase Setup Guide

This directory contains all the necessary configuration and migration files for our Supabase database. Follow these steps to set up your local development environment.

## Prerequisites

1. Install [Supabase CLI](https://supabase.com/docs/guides/cli)
2. Install [Docker](https://docs.docker.com/get-docker/)

## Setup Steps

1. **Install Supabase CLI** (if not already installed):
   ```bash
   # Windows (requires scoop)
   scoop install supabase

   # macOS
   brew install supabase/tap/supabase
   ```

2. **Login to Supabase CLI**:
   ```bash
   supabase login
   ```

3. **Utilize UTBT Auth Bootstrap**:
   We offer a bootstrap script that'll help get your Supabase database configured.
   ```bash
   ./scripts/bootstrap
   ```

## Directory Structure

- `/migrations`: Contains all database migrations
- `/seed`: Contains seed data for development
- `config.toml`: Supabase configuration file

## Environment Variables

Make sure to copy `.env.example` to `.env` and update the following variables:

```
SUPABASE_URL=your_supabase_url
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key
```

For local development, you can find these values after running `supabase start`.

## Additional Resources

- [Supabase CLI Documentation](https://supabase.com/docs/reference/cli)
- [Supabase Migration Guides](https://supabase.com/docs/guides/database/migrations)
- [Database Configuration](https://supabase.com/docs/guides/database/config) 