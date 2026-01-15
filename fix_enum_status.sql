-- ============================================================================
-- CRITICAL FIX: Ensure scan_status_enum uses lowercase labels only
-- Run this SQL in pgAdmin or psql to fix the database enum
-- ============================================================================

-- Step 1: Drop and recreate the enum with LOWERCASE labels only
-- WARNING: This will fail if the type is in use. We'll handle that below.

-- First, let's check what the current enum values are:
-- SELECT enumlabel FROM pg_enum WHERE enumtypid = 'scan_status_enum'::regtype ORDER BY enumsortorder;

-- Step 2: Create a temporary enum with correct lowercase values
CREATE TYPE scan_status_enum_new AS ENUM (
    'queued',
    'cloning',
    'analyzing',
    'scanning',
    'scanning_semgrep',
    'scanning_codeql',
    'completed',
    'failed',
    'cancelled'
);

-- Step 3: Alter the scan_history.status column to use the new enum
-- First, cast existing values to lowercase
ALTER TABLE scan_history 
    ALTER COLUMN status TYPE scan_status_enum_new USING (
        LOWER(status::text)::scan_status_enum_new
    );

-- Step 4: Drop the old enum
DROP TYPE scan_status_enum;

-- Step 5: Rename the new enum to the original name
ALTER TYPE scan_status_enum_new RENAME TO scan_status_enum;

-- Step 6: Verify the fix
SELECT enumlabel FROM pg_enum WHERE enumtypid = 'scan_status_enum'::regtype ORDER BY enumsortorder;

-- ============================================================================
-- ALTERNATIVE: If the above fails due to dependencies, use this approach:
-- ============================================================================

-- Check current enum values
-- SELECT enumlabel, enumsortorder FROM pg_enum 
-- WHERE enumtypid = 'scan_status_enum'::regtype 
-- ORDER BY enumsortorder;

-- If you see uppercase values (e.g., 'QUEUED'), you MUST fix the PostgreSQL type.
-- Contact your database admin to run the recreation steps above.
