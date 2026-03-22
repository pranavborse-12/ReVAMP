"""
Downloads Semgrep rules directly from Registry API.
No --dump-config flag needed. Works with any Semgrep version.
"""
import os
import httpx
import yaml

RULES_DIR = r"backend\scanning_repos\semgrep_rules"
os.makedirs(RULES_DIR, exist_ok=True)

# Read token from .env
from dotenv import load_dotenv
load_dotenv()
TOKEN = os.getenv("SEMGREP_APP_TOKEN", "")

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/json",
}

PACKS = [
    # Universal
    ("p/owasp-top-ten",      "owasp.yaml"),
    ("p/cwe-top-25",         "cwe.yaml"),
    ("p/secrets",            "secrets.yaml"),
    # Python
    ("p/python",             "python.yaml"),
    ("p/django",             "django.yaml"),
    ("p/flask",              "flask.yaml"),
    # JavaScript
    ("p/javascript",         "javascript.yaml"),
    ("p/typescript",         "typescript.yaml"),
    ("p/react",              "react.yaml"),
    ("p/nodejs",             "nodejs.yaml"),
    # Java
    ("p/java",               "java.yaml"),
    ("p/spring",             "spring.yaml"),
    # Other languages
    ("p/golang",             "golang.yaml"),
    ("p/ruby",               "ruby.yaml"),
    ("p/php",                "php.yaml"),
    ("p/rust",               "rust.yaml"),
    # Security specific
    ("p/sql-injection",      "sql-injection.yaml"),
    ("p/xss",                "xss.yaml"),
    ("p/jwt",                "jwt.yaml"),
    ("p/cryptography",       "cryptography.yaml"),
    ("p/cors",               "cors.yaml"),
    # DevOps
    ("p/docker",             "docker.yaml"),
    ("p/terraform",          "terraform.yaml"),
    ("p/kubernetes",         "kubernetes.yaml"),
    ("p/github-actions",     "github-actions.yaml"),
]

success = []
failed = []

print(f"Downloading {len(PACKS)} rule packs from Semgrep Registry...\n")

with httpx.Client(timeout=30, headers=HEADERS) as client:
    for pack, filename in PACKS:
        # Convert p/owasp-top-ten -> owasp-top-ten
        pack_name = pack.replace("p/", "")
        url = f"https://semgrep.dev/c/{pack}"
        print(f"  {pack:<30}", end=" ", flush=True)

        try:
            resp = client.get(url)

            if resp.status_code == 401:
                print("✗  401 Unauthorized — token invalid")
                failed.append(pack)
                continue

            if resp.status_code == 404:
                print("✗  404 Not found — pack may not exist")
                failed.append(pack)
                continue

            if resp.status_code != 200:
                print(f"✗  HTTP {resp.status_code}")
                failed.append(pack)
                continue

            # Parse and validate
            content = resp.text
            data = yaml.safe_load(content)
            rules = data.get("rules", []) if data else []

            if not rules:
                print(f"⚠  0 rules returned")
                failed.append(pack)
                continue

            # Save
            output_path = os.path.join(RULES_DIR, filename)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)

            print(f"✓  {len(rules)} rules")
            success.append((pack, len(rules)))

        except httpx.TimeoutException:
            print("✗  timeout")
            failed.append(pack)
        except Exception as e:
            print(f"✗  {e}")
            failed.append(pack)

print(f"\n{'='*50}")
print(f"✓  Downloaded: {len(success)}")
print(f"✗  Failed:     {len(failed)}")
if failed:
    print(f"\nFailed: {failed}")