"""
Database Verification Script - FIXED
Tests database connectivity and table structure
"""
import asyncio
import uuid
from datetime import datetime, timezone
from sqlalchemy import text, inspect
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.config import init_database, get_db, is_db_available, get_engine
from backend.database.scan_models import Repository, ScanHistory, Vulnerability, ScanStatistics


async def verify_database():
    """Comprehensive database verification"""
    print("\nStarting database verification...\n")
    print("=" * 80)
    print("DATABASE VERIFICATION")
    print("=" * 80)
    
    # ========================================
    # STEP 1: Test Connection
    # ========================================
    print("\n1. Testing database connection...")
    
    db_init = await init_database()
    
    if not db_init:
        print("   ❌ FAILED: Could not initialize database")
        print("\nPlease check:")
        print("  1. PostgreSQL is running")
        print("  2. DATABASE_URL is correct in .env")
        print("  3. Database 'revamp_db' exists")
        return False
    
    print("   [OK] SUCCESS: Database connected")
    
    # ========================================
    # STEP 2: Verify Tables Exist
    # ========================================
    print("\n2. Verifying database tables...")
    
    try:
        engine = get_engine()
        async with engine.connect() as conn:
            # Check if tables exist
            result = await conn.execute(text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name IN ('repositories', 'scan_history', 'vulnerabilities', 'scan_statistics')
                ORDER BY table_name
            """))
            
            tables = [row[0] for row in result.fetchall()]
            
            expected_tables = ['repositories', 'scan_history', 'scan_statistics', 'vulnerabilities']
            
            for table in expected_tables:
                if table in tables:
                    print(f"   ✅ {table}")
                else:
                    print(f"   ❌ {table} - MISSING")
            
            if len(tables) == len(expected_tables):
                print(f"\n   ✅ SUCCESS: All {len(expected_tables)} tables exist")
            else:
                print(f"\n   ❌ FAILED: Only {len(tables)}/{len(expected_tables)} tables found")
                print("\n   Run the SQL schema in pgAdmin first!")
                return False
                
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        return False
    
    # ========================================
    # STEP 3: Test Table Accessibility
    # ========================================
    print("\n3. Testing table accessibility...")
    
    try:
        async for db in get_db():
            try:
                # Count records in each table
                repo_count = await db.execute(text("SELECT COUNT(*) FROM repositories"))
                scan_count = await db.execute(text("SELECT COUNT(*) FROM scan_history"))
                vuln_count = await db.execute(text("SELECT COUNT(*) FROM vulnerabilities"))
                stats_count = await db.execute(text("SELECT COUNT(*) FROM scan_statistics"))
                
                print(f"   ✅ repositories - {repo_count.scalar()} records")
                print(f"   ✅ scan_history - {scan_count.scalar()} records")
                print(f"   ✅ vulnerabilities - {vuln_count.scalar()} records")
                print(f"   ✅ scan_statistics - {stats_count.scalar()} records")
                
                print("\n   ✅ SUCCESS: All tables accessible")
                break
                
            except Exception as e:
                print(f"   ❌ FAILED: {e}")
                return False
                
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        return False
    
    # ========================================
    # STEP 4: Test Write Operations - FIXED
    # ========================================
    print("\n4. Testing write operations...")
    
    try:
        async for db in get_db():
            try:
                # Create test repository
                test_repo = Repository(
                    id=uuid.uuid4(),
                    user_id=uuid.uuid4(),
                    owner="test_owner",
                    name="test_repo",
                    full_name="test_owner/test_repo",
                    github_url="https://github.com/test_owner/test_repo",
                    default_branch="main"
                )
                db.add(test_repo)
                await db.flush()
                
                # CRITICAL FIX: Use lowercase string for status
                test_scan = ScanHistory(
                    id=uuid.uuid4(),
                    scan_id=f"test_{uuid.uuid4()}",
                    user_id=test_repo.user_id,
                    repository_id=test_repo.id,
                    branch_name="main",
                    scanner_mode="test",
                    status="queued",  # ← FIXED: lowercase string
                    total_vulnerabilities=0,
                    critical_count=0,
                    high_count=0,
                    medium_count=0,
                    low_count=0,
                    info_count=0,
                    warning_count=0,
                    queued_at=datetime.now(timezone.utc)
                )
                db.add(test_scan)
                
                # Commit transaction
                await db.commit()
                
                print("   ✅ SUCCESS: Write operations working")

                # Also ensure uppercase status is normalized by model validator
                test_scan_upper = ScanHistory(
                    id=uuid.uuid4(),
                    scan_id=f"test_upper_{uuid.uuid4()}",
                    user_id=test_repo.user_id,
                    repository_id=test_repo.id,
                    branch_name="main",
                    scanner_mode="test",
                    status="queued",  # Start with lowercase
                    total_vulnerabilities=0,
                    critical_count=0,
                    high_count=0,
                    medium_count=0,
                    low_count=0,
                    info_count=0,
                    warning_count=0,
                    queued_at=datetime.now(timezone.utc)
                )
                # Now assign uppercase to trigger the validator
                test_scan_upper.status = "QUEUED"  # intentionally uppercase
                db.add(test_scan_upper)
                await db.flush()
                # Validator should have normalized to lowercase
                if test_scan_upper.status != 'queued':
                    print("   ❌ FAILED: Uppercase status was not normalized by model validator")
                    await db.rollback()
                    return False
                else:
                    print("   ✅ Uppercase status normalized to 'queued' by model validator")

                # Clean up test data
                await db.delete(test_scan_upper)
                await db.delete(test_scan)
                await db.delete(test_repo)
                await db.commit()

                print("   ✅ SUCCESS: Cleanup completed")
                break
                
            except Exception as e:
                await db.rollback()
                print(f"   ❌ FAILED: {e}")
                import traceback
                traceback.print_exc()
                return False
                
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        return False
    
    # ========================================
    # STEP 5: Verify Enum Types
    # ========================================
    print("\n5. Verifying enum types...")
    
    try:
        async with engine.connect() as conn:
            # Check scan_status_enum
            result = await conn.execute(text("""
                SELECT enumlabel 
                FROM pg_enum 
                WHERE enumtypid = 'scan_status_enum'::regtype
                ORDER BY enumsortorder
            """))
            status_values = [row[0] for row in result.fetchall()]
            
            print(f"   scan_status_enum values: {', '.join(status_values)}")
            
            expected_status = ['queued', 'cloning', 'analyzing', 'scanning', 
                             'scanning_semgrep', 'scanning_codeql', 'completed', 
                             'failed', 'cancelled']
            
            if all(v in status_values for v in expected_status):
                print("   ✅ scan_status_enum is correct")
            else:
                print("   ⚠️  scan_status_enum may be incomplete")
            
            # Check severity_enum
            result = await conn.execute(text("""
                SELECT enumlabel 
                FROM pg_enum 
                WHERE enumtypid = 'severity_enum'::regtype
                ORDER BY enumsortorder
            """))
            severity_values = [row[0] for row in result.fetchall()]
            
            print(f"   severity_enum values: {', '.join(severity_values)}")
            
            expected_severity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'WARNING']
            
            if all(v in severity_values for v in expected_severity):
                print("   ✅ severity_enum is correct")
            else:
                print("   ⚠️  severity_enum may be incomplete")
                
    except Exception as e:
        print(f"   ⚠️  Could not verify enums: {e}")
    
    # ========================================
    # SUCCESS
    # ========================================
    print("\n" + "=" * 80)
    print("✅ DATABASE VERIFICATION SUCCESSFUL")
    print("=" * 80)
    print("\nYour database is properly configured and ready to use!")
    return True


async def main():
    """Main entry point"""
    try:
        success = await verify_database()
        
        if not success:
            print("\n" + "=" * 80)
            print("❌ Database verification failed!")
            print("=" * 80)
            print("\nPlease:")
            print("  1. Check your DATABASE_URL in .env")
            print("  2. Ensure PostgreSQL is running")
            print("  3. Run the SQL schema in pgAdmin first")
            return
            
    except Exception as e:
        print(f"\n❌ Verification error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())