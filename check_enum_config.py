"""
Check PostgreSQL enum configuration
Run this to verify your database enum has lowercase labels
"""
import asyncio
import sys
sys.path.insert(0, '.')

from backend.database.config import get_engine
from sqlalchemy import text


async def check_enum_config():
    """Verify scan_status_enum has correct lowercase labels"""
    
    print("\n" + "="*80)
    print("CHECKING POSTGRESQL ENUM CONFIGURATION")
    print("="*80 + "\n")
    
    try:
        engine = get_engine()
        async with engine.connect() as conn:
            # Get enum values
            result = await conn.execute(text("""
                SELECT enumlabel 
                FROM pg_enum 
                WHERE enumtypid = 'scan_status_enum'::regtype
                ORDER BY enumsortorder
            """))
            
            enum_values = [row[0] for row in result.fetchall()]
            
            if not enum_values:
                print("❌ ERROR: scan_status_enum not found in database!")
                print("   Make sure you created the enum in PostgreSQL first.")
                return False
            
            print("Current scan_status_enum values:")
            for i, val in enumerate(enum_values, 1):
                is_lowercase = val.islower()
                status = "✅" if is_lowercase else "⚠️ "
                print(f"   {i}. '{val}' {status}")
            
            # Check if any are uppercase
            uppercase_found = [v for v in enum_values if not v.islower()]
            
            if uppercase_found:
                print(f"\n⚠️  WARNING: Found {len(uppercase_found)} uppercase labels:")
                for val in uppercase_found:
                    print(f"   - '{val}' (should be '{val.lower()}')")
                print("\n📋 To fix, run:")
                print("   psql -U postgres -d revamp_db < fix_enum_status.sql")
                return False
            else:
                print("\n✅ SUCCESS: All enum labels are lowercase!")
                
                # Verify all expected values exist
                expected = {
                    'queued', 'cloning', 'analyzing', 'scanning',
                    'scanning_semgrep', 'scanning_codeql',
                    'completed', 'failed', 'cancelled'
                }
                actual = set(enum_values)
                
                if expected.issubset(actual):
                    print("✅ All expected status values present")
                    return True
                else:
                    missing = expected - actual
                    print(f"\n⚠️  Missing values: {missing}")
                    print("   These can be added via migration if needed.")
                    return True
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
        print("\nMake sure:")
        print("  1. PostgreSQL is running")
        print("  2. DATABASE_URL in .env is correct")
        print("  3. Database 'revamp_db' exists")
        return False


if __name__ == "__main__":
    success = asyncio.run(check_enum_config())
    print("\n" + "="*80)
    if success:
        print("✅ Database configuration is correct!")
    else:
        print("❌ Database configuration needs attention")
    print("="*80 + "\n")
    sys.exit(0 if success else 1)
