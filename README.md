Task 3: Secure Coding Review 🔐
Overview
A security vulnerability audit performed on a Python Flask web application.
Vulnerabilities were identified using manual code inspection and static analysis tools, followed by remediation.

Language & Framework

Language: Python 3.x
Framework: Flask (Micro Web Framework)
Review Method: Static Analysis + Manual Inspection


Application Endpoints Reviewed
EndpointMethodVulnerability Found/loginPOSTSQL Injection/greetGETServer-Side Template Injection (SSTI)/pingGETOS Command Injectionapp.py—Hardcoded Secret Key + Debug Mode

Vulnerabilities Found
1. 🔴 SQL Injection (CWE-89) — CRITICAL
Location: /login endpoint
Issue: User input directly interpolated into SQL query string.
Attack: ' OR '1'='1 — bypasses authentication entirely.
python# Vulnerable
q = f"SELECT * FROM users WHERE username='{user}' AND password='{pwd}'"

# Fixed
q = "SELECT * FROM users WHERE username=? AND password=?"
db.execute(q, (user, pwd))

2. 🟠 Server-Side Template Injection (CWE-94) — HIGH
Location: /greet endpoint
Issue: User input embedded directly inside a Jinja2 template string.
Attack: {{config}} leaks secret keys; {{''.__class__.__mro__}} can lead to RCE.
python# Vulnerable
tmpl = f"<h1>Hello {name}!</h1>"
return render_template_string(tmpl)

# Fixed
tmpl = "<h1>Hello {{ name }}!</h1>"
return render_template_string(tmpl, name=name)

3. 🟠 OS Command Injection (CWE-78) — HIGH
Location: /ping endpoint
Issue: host param passed directly to shell with shell=True.
Attack: 8.8.8.8; rm -rf / — runs arbitrary OS commands on the server.
python# Vulnerable
out = subprocess.check_output(f"ping -c 1 {host}", shell=True)

# Fixed
if not re.match(r"^[\w.\-]+$", host):
    return "Invalid host", 400
out = subprocess.check_output(["ping", "-c", "1", host])

4. 🔵 Hardcoded Secret Key + Debug Mode (CWE-321) — MEDIUM
Location: app.py global config
Issue: Secret key committed in source code; debug mode exposes Werkzeug console.
python# Vulnerable
app.secret_key = "admin123"
app.run(debug=True)

# Fixed
app.secret_key = os.environ["SECRET_KEY"]
app.run(debug=False)

Summary
SeverityCount🔴 Critical1🟠 High2🔵 Medium1🟢 Low0Total4

Static Analysis Tools Used
ToolCommandPurposeBanditbandit -r app.pyPython SAST — shell injection, hardcoded passwordsSemgrepsemgrep --config=p/flask app.pyFlask/OWASP rulesets — SQLi, SSTI, command injectionSafetysafety checkScans packages against CVE databasePylintpylint app.pyCode quality — debug=True, antipatterns

Remediation Steps

Parameterized queries — use ? placeholders, never f-strings in SQL
Safe templating — pass user data as context variables, never embed in template string
No shell=True — use list-form subprocess + whitelist regex validation
Externalize secrets — use os.environ or secrets manager (HashiCorp Vault, AWS Secrets Manager)
Disable debug in production — set FLASK_ENV=production
CI/CD integration — run Bandit + Semgrep on every pull request


Files
FileDescriptionTask3_SecureCodingReview.docxFull detailed report (Word document)README.mdThis file

References

OWASP Top 10
CWE-89: SQL Injection
CWE-94: Code Injection
CWE-78: OS Command Injection
Bandit Documentation
Semgrep Rules
