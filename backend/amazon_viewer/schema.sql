-- backend/schema.sql
-- Defines the tables for user management and settings.
-- This script is idempotent and can be run multiple times safely.

-- Create a UUID extension if it doesn't exist, for generating unique IDs.
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Table to store user login information
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user', -- ADDED: Role for the user (e.g., 'user', 'admin')
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Table to store user-specific settings, like encrypted Amazon credentials
CREATE TABLE IF NOT EXISTS user_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID UNIQUE NOT NULL,
    amazon_email VARCHAR(255),
    amazon_password_encrypted BYTEA,
    amazon_otp_secret_key VARCHAR(255),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_user
        FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE CASCADE -- If a user is deleted, their settings are also deleted.
);

-- Optional: Create an index on user_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_user_settings_user_id ON user_settings(user_id);
