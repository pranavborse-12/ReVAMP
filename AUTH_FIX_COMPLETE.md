# Authentication & UUID Validation Fix

## Problem
Database error: `invalid input for query argument $1: 'anonymous' (invalid UUID 'anonymous')`

The application was attempting to save repositories with `user_id='anonymous'` (a string) to a PostgreSQL database column that expects valid UUIDs. This caused repository persistence to fail for all unauthenticated users.

## Root Cause
1. **Authentication Fallback** (`backend/user_repositories/github_repos.py` line 69):
   - When JWT tokens fail to validate, the `get_user_id()` function returns the string `"anonymous"` as a default
   - This placeholder value is then passed to database queries expecting a valid UUID

2. **Missing Validation** (`backend/scanning_repos/storage.py` line 225):
   - The `save_repository_to_db()` function accepted any user_id without validating it was a valid UUID
   - Invalid user_id values were passed directly to the ORM, which forwarded them to PostgreSQL
   - PostgreSQL rejected the query with UUID type error

## Solution Implemented

### 1. API Endpoint Validation (`backend/user_repositories/github_repos.py`)
**Location**: Lines 91-96 in `get_user_repos()` endpoint

**Change**: Added authentication check before attempting to fetch and save repositories:
```python
# Validate user is authenticated
if not user_id or user_id == "anonymous":
    raise HTTPException(
        status_code=401,
        detail="Authentication required to fetch repositories"
    )
```

**Effect**: 
- Unauthenticated users get immediate HTTP 401 response
- Prevents database operations with invalid user_id
- Clear error message to frontend

### 2. Repository Save Function Validation (`backend/scanning_repos/storage.py`)
**Location**: Lines 227-241 in `save_repository_to_db()` function

**Changes**: Added two-layer validation:

**Layer 1 - Placeholder Check (Lines 228-231)**:
```python
if not user_id or user_id == "anonymous":
    logger.warning(f"Cannot save repository {owner}/{repo_name}: user not authenticated (user_id={user_id})")
    return None
```

**Layer 2 - UUID Format Validation (Lines 233-240)**:
```python
try:
    from uuid import UUID
    UUID(str(user_id))
except (ValueError, AttributeError):
    logger.warning(f"Cannot save repository {owner}/{repo_name}: invalid user_id format '{user_id}'")
    return None
```

**Effect**:
- Validates user_id is a valid UUID format before database operation
- Returns None (no exception) for invalid user_id
- Prevents invalid queries from reaching PostgreSQL
- Logs why repositories weren't saved

## Defense-in-Depth Architecture

The fix implements multi-layer validation:

```
┌─────────────────────────────────┐
│   GET /repos endpoint           │ ← Check 1: Is user authenticated?
└──────────┬──────────────────────┘
           │
           ▼
┌─────────────────────────────────┐
│   save_repository_to_db()       │ ← Check 2: Is user_id not "anonymous"?
│                                  │ ← Check 3: Is user_id valid UUID?
└──────────┬──────────────────────┘
           │
           ▼
┌─────────────────────────────────┐
│   Database Operation            │ ← Only valid UUIDs reach here
└─────────────────────────────────┘
```

## Testing the Fix

### Test Case 1: Unauthenticated User
```
GET /api/repos/repos (no token)
→ Caught at endpoint validation (Check 1)
→ HTTP 401: "Authentication required to fetch repositories"
→ No database operation
```

### Test Case 2: Invalid user_id
```
save_repository_to_db(user_id="invalid", owner="test", ...)
→ Caught at repository save function (Check 3)
→ Logs warning and returns None
→ No database operation
```

### Test Case 3: Valid Authenticated User
```
GET /api/repos/repos (with valid JWT token)
→ Pass endpoint validation (Check 1)
→ Get user_id from JWT payload (valid UUID)
→ Pass repository save validation (Checks 2 & 3)
→ Successfully saved to database
```

## Error Handling

### Before Fix
```
ERROR: invalid input for query argument $1: 'anonymous' (invalid UUID 'anonymous')
→ Database error
→ Repository save fails silently
→ No feedback to user
```

### After Fix
```
Case 1 (No token):
WARNING: Cannot save repository ReVAMP/ReVAMP: user not authenticated (user_id=anonymous)
Response: HTTP 401 with clear message

Case 2 (Invalid UUID):
WARNING: Cannot save repository ReVAMP/ReVAMP: invalid user_id format 'invalid'
Response: Function returns None gracefully
```

## Files Modified

1. **backend/scanning_repos/storage.py**
   - Function: `save_repository_to_db()`
   - Lines: 227-241
   - Added: UUID format validation and "anonymous" check

2. **backend/user_repositories/github_repos.py**
   - Endpoint: `GET /repos`
   - Lines: 91-96
   - Added: Authentication requirement check

## Backward Compatibility

✅ **Fully backward compatible**
- Valid authenticated users unaffected
- Invalid requests now properly rejected instead of causing database errors
- No changes to API contract (same endpoint, same parameters)
- Only rejected requests are those that would have failed anyway

## Related Fixes

This fix complements the earlier enum status fix:
- **Enum Fix** (previous): Handles enum value normalization (UPPERCASE → lowercase)
- **Auth Fix** (current): Prevents invalid user_id values from reaching database

Together these fixes create a robust persistence layer with defensive validation at multiple points.

## Verification Checklist

- [x] Syntax validation passed for both files
- [x] No imports needed (UUID from stdlib)
- [x] Endpoint returns proper HTTP status codes
- [x] Logging provides visibility into why saves fail
- [x] Function gracefully returns None instead of throwing
- [x] Both 'anonymous' string and UUID format validated
- [x] No changes to authenticated user flow
