import yaml
import os

RULES_DIR = r"backend\scanning_repos\semgrep_rules"

def load_rules(filename):
    path = os.path.join(RULES_DIR, filename)
    if not os.path.exists(path):
        print(f"  ⚠  Missing: {filename}")
        return []
    try:
        data = yaml.safe_load(open(path, encoding="utf-8"))
        rules = data.get("rules", [])
        print(f"  ✓  {filename}: {len(rules)} rules")
        return rules
    except Exception as e:
        print(f"  ✗  {filename}: {e}")
        return []

def build_master(name, files):
    print(f"\nBuilding master-{name}.yaml...")
    all_rules = []
    seen_ids = set()

    for f in files:
        for rule in load_rules(f):
            rule_id = rule.get("id", "")
            if rule_id and rule_id not in seen_ids:
                seen_ids.add(rule_id)
                all_rules.append(rule)

    if not all_rules:
        print(f"  ✗  No rules found — skipping")
        return

    output = os.path.join(RULES_DIR, f"master-{name}.yaml")
    with open(output, "w", encoding="utf-8") as f:
        yaml.dump({"rules": all_rules}, f,
                  allow_unicode=True,
                  default_flow_style=False,
                  sort_keys=False)

    print(f"  → master-{name}.yaml: {len(all_rules)} unique rules")

# ── Build each master file ──────────────────────────────────────

build_master("universal", [
    "owasp.yaml",
    "cwe.yaml",
    "secrets.yaml",
    "sql-injection.yaml",
    "xss.yaml",
    "jwt.yaml",
    "cryptography.yaml",
    "cors.yaml",
    "insecure-transport.yaml",
])

build_master("python", [
    "python.yaml",
    "django.yaml",
    "flask.yaml",
])

build_master("javascript", [
    "javascript.yaml",
    "typescript.yaml",
    "react.yaml",
    "nodejs.yaml",
])

build_master("java", [
    "java.yaml",
    "spring.yaml",
])

build_master("golang", [
    "golang.yaml",
])

build_master("ruby", [
    "ruby.yaml",
])

build_master("php", [
    "php.yaml",
])

build_master("systems", [
    "rust.yaml",
])

build_master("devops", [
    "docker.yaml",
    "terraform.yaml",
    "kubernetes.yaml",
    "github-actions.yaml",
])

print("\n" + "="*50)
print("Master files built. Final structure:")
for f in sorted(os.listdir(RULES_DIR)):
    if f.startswith("master-"):
        size = os.path.getsize(os.path.join(RULES_DIR, f))
        print(f"  {f:<35} {size//1024} KB")