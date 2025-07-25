#!/usr/bin/env python3
import os
print("🔍 CHECKING FOR LEGACY REFERENCES")
print("=" * 50)
print(f"Current directory: {os.getcwd()}")

# Check the current file
try:
    with open("nmx_table_analyzer.py", "r") as f:
        content = f.read()
    
    legacy_count = content.lower().count("legacy")
    if legacy_count == 0:
        print("✅ NO LEGACY REFERENCES FOUND IN CURRENT FILE!")
        print("✅ This file is clean and ready to use.")
    else:
        print(f"❌ Found {legacy_count} legacy references!")
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if 'legacy' in line.lower():
                print(f"  Line {i}: {line.strip()}")
except Exception as e:
    print(f"❌ Error: {e}")

print("\n🎯 TO FIX: Run this command:")
print("   sed -i '' '/[Ll]egacy/d' nmx_table_analyzer.py")
