import subprocess
import requests
import sys
import os

print("=" * 50)
print("AI SOC ANALYZER - SETUP CHECKER")
print("=" * 50)

# Check Python version
print(f"\n📌 Python version: {sys.version}")
print(f"📌 Working directory: {os.getcwd()}")
print(f"📌 Python executable: {sys.executable}")

# Check Python packages
print("\n📦 CHECKING PYTHON PACKAGES:")
try:
    import requests
    print(f"   ✅ requests installed (version: {requests.__version__})")
except ImportError:
    print("   ❌ requests not installed")
    print("      Run: pip install requests")

# Check Nmap - specifically looking in your F drive location
print("\n🔍 CHECKING NMAP:")

nmap_found = False
nmap_location = None

# First, check if nmap is in PATH
try:
    result = subprocess.run(["nmap", "--version"], 
                          capture_output=True, 
                          text=True, 
                          timeout=5,
                          shell=True)
    if result.returncode == 0:
        print("   ✅ Nmap found in system PATH")
        print(f"      Version: {result.stdout.split(chr(10))[0]}")
        nmap_found = True
        nmap_location = "nmap (in PATH)"
except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
    pass

# If not in PATH, check your specific F drive location
if not nmap_found:
    f_drive_path = r"F:\Program Files (x86)\Nmap\nmap.exe"
    print(f"   🔍 Checking specific location: {f_drive_path}")
    
    if os.path.exists(f_drive_path):
        print(f"   ✅ Nmap executable found at: {f_drive_path}")
        try:
            result = subprocess.run([f_drive_path, "--version"], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            if result.returncode == 0:
                print(f"      Version: {result.stdout.split(chr(10))[0]}")
                print("      ✅ Nmap is working correctly")
                nmap_found = True
                nmap_location = f_drive_path
            else:
                print("      ❌ Nmap executable found but not working properly")
        except Exception as e:
            print(f"      ❌ Error running Nmap: {e}")
    else:
        print(f"   ❌ Nmap not found at: {f_drive_path}")
        
        # Check if the directory exists
        nmap_dir = r"F:\Program Files (x86)\Nmap"
        if os.path.exists(nmap_dir):
            print(f"   📁 Directory exists: {nmap_dir}")
            print(f"   📄 Contents of Nmap directory:")
            try:
                for file in os.listdir(nmap_dir)[:10]:  # Show first 10 files
                    print(f"      - {file}")
                if len(os.listdir(nmap_dir)) > 10:
                    print(f"      ... and {len(os.listdir(nmap_dir))-10} more files")
            except:
                print("      Could not list directory contents")
        else:
            print(f"   ❌ Directory does not exist: {nmap_dir}")

if not nmap_found:
    print("\n   ❌ Nmap not found in any location")
    print("   Please install Nmap from: https://nmap.org/download.html")
    print("   Or if already installed, make sure it's in the correct location")

# Check Ollama
print("\n🤖 CHECKING OLLAMA:")

try:
    response = requests.get("http://localhost:11434/api/tags", timeout=5)
    if response.status_code == 200:
        print("   ✅ Ollama is running")
        models = response.json().get("models", [])
        if models:
            model_names = [m['name'] for m in models]
            print(f"   ✅ Models available: {model_names}")
            if 'mistral:latest' in model_names:
                print("   ✅ Mistral model is ready")
            else:
                print("   ⚠️  Mistral model not found. Run: ollama pull mistral")
        else:
            print("   ⚠️  No models found. Run: ollama pull mistral")
    else:
        print("   ❌ Ollama returned unexpected response")
except requests.exceptions.ConnectionError:
    print("   ❌ Cannot connect to Ollama")
    print("      Start Ollama from Windows Start Menu")
except Exception as e:
    print(f"   ❌ Error checking Ollama: {e}")

# Check known_devices.json
print("\n📁 CHECKING CONFIG FILES:")
if os.path.exists("known_devices.json"):
    print("   ✅ known_devices.json exists")
    try:
        with open("known_devices.json", "r") as f:
            import json
            data = json.load(f)
            print(f"      Contains {len(data)} known devices")
    except json.JSONDecodeError:
        print("   ⚠️  known_devices.json is corrupted (invalid JSON)")
        print("      Recreating file...")
        with open("known_devices.json", "w") as f:
            json.dump([], f)
        print("   ✅ Recreated known_devices.json")
else:
    print("   ⚠️  known_devices.json not found")
    print("      Creating empty file...")
    with open("known_devices.json", "w") as f:
        json.dump([], f)
    print("   ✅ Created known_devices.json")

# Check if we can run nmap from Python
print("\n🔄 TESTING NMAP FROM PYTHON:")
if nmap_found:
    try:
        if nmap_location == "nmap (in PATH)":
            test_cmd = "nmap --version"
        else:
            test_cmd = f'"{nmap_location}" --version'
        
        print(f"   Running: {test_cmd}")
        result = subprocess.run(test_cmd, 
                              capture_output=True, 
                              text=True, 
                              timeout=5,
                              shell=True)
        if result.returncode == 0:
            print("   ✅ Python can successfully run Nmap")
        else:
            print("   ❌ Python can't run Nmap properly")
    except Exception as e:
        print(f"   ❌ Error testing Nmap from Python: {e}")
else:
    print("   ⚠️  Cannot test Nmap - not found")

# Summary
print("\n" + "=" * 50)
print("SETUP SUMMARY:")
print("=" * 50)

if nmap_found:
    print("✅ Nmap: FOUND")
    print(f"   Location: {nmap_location}")
else:
    print("❌ Nmap: NOT FOUND - REQUIRED for network scanning")

try:
    import requests
    print("✅ Requests: INSTALLED")
except:
    print("❌ Requests: NOT INSTALLED - Run: pip install requests")

try:
    requests.get("http://localhost:11434/api/tags", timeout=2)
    print("✅ Ollama: RUNNING")
    print("   Mistral model: READY")
except:
    print("⚠️  Ollama: NOT RUNNING - AI analysis will fail")

print("\n" + "=" * 50)
print("NEXT STEPS:")

if not nmap_found:
    print("❌ FIX NMAP ISSUE FIRST:")
    print("   1. Verify Nmap is installed at: F:\\Program Files (x86)\\Nmap")
    print("   2. If it exists, check permissions")
    print("   3. Or add to PATH: F:\\Program Files (x86)\\Nmap")
else:
    print("✅ Nmap is good!")
    
try:
    import requests
    print("✅ Python packages are good!")
except:
    print("❌ Run: pip install requests")
    
print("\nAfter fixing issues, run: python ai_soc.py")
print("=" * 50)