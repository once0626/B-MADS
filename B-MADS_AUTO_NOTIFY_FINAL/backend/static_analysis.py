import hashlib
import yara
import os
import math

RULES_PATH = "yara_rules/rules.yar"

# -------------------------
# Hash calculation
# -------------------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

# -------------------------
# Entropy calculation
# -------------------------
def calculate_entropy(data):
    if not data:
        return 0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0
    for f in freq.values():
        p = f / len(data)
        ent -= p * math.log2(p)
    return ent

# -------------------------
# Main static analysis
# -------------------------
def analyze_file(path):
    sha = sha256_file(path)

    filename = os.path.basename(path)
    extension = os.path.splitext(path)[1].lower()
    filesize = os.path.getsize(path)

    # -------------------------
    # YARA matching (highest priority)
    # -------------------------
    rules = yara.compile(filepath=RULES_PATH)
    matches = rules.match(path)

    if matches:
        return {
            "metadata": {
                "filename": filename,
                "extension": extension,
                "size_bytes": filesize
            },
            "analysis": {
                "sha256": sha,
                "yara_match": True,
                "verdict": "Malicious",
                "details": [m.rule for m in matches]
            }
        }

    # -------------------------
    # Heuristic static analysis
    # -------------------------
    score = 0
    reasons = []

    with open(path, "rb") as f:
        data = f.read()

    data_lower = data.lower()

    # 1️⃣ URL detection (ONLY for text-based formats)
    TEXT_EXTENSIONS = [".txt", ".html", ".htm", ".js", ".ps1", ".vbs"]

    if extension in TEXT_EXTENSIONS:
        if b"http://" in data_lower or b"https://" in data_lower:
            score += 20
            reasons.append("Suspicious URL detected in text content")

    # 2️⃣ Executable files
    EXECUTABLE_EXTENSIONS = [".exe", ".dll", ".scr"]

    if extension in EXECUTABLE_EXTENSIONS:
        score += 30
        reasons.append("Executable file detected")

        if filesize < 100 * 1024:
            score += 15
            reasons.append("Unusually small executable")

    # 3️⃣ Script files
    SCRIPT_EXTENSIONS = [".js", ".vbs", ".ps1", ".bat"]

    if extension in SCRIPT_EXTENSIONS:
        score += 25
        reasons.append("Script-based file detected")

    # 4️⃣ Office documents (macro awareness)
    MACRO_OFFICE_FILES = [".docm", ".xlsm", ".pptm"]

    if extension in MACRO_OFFICE_FILES:
        score += 30
        reasons.append("Macro-enabled Office document detected")

    # 5️⃣ PDF documents (FALSE POSITIVE FIX HERE 🔥)
    if extension == ".pdf":
        suspicious_keywords = [
            b"/javascript",
            b"/openaction",
            b"/launch",
            b"/embeddedfile",
            b"/aa"
        ]

        has_active_content = any(k in data_lower for k in suspicious_keywords)

        entropy = calculate_entropy(data)

        # 🔥 entropy ONLY matters if active content exists
        if entropy > 7.5 and has_active_content:
            score += 25
            reasons.append("High entropy with active PDF content detected")
        else:
            reasons.append("PDF document analyzed (scanned / image-based or no active content)")

    # -------------------------
    # Final verdict logic
    # -------------------------
    if score == 0:
        verdict = "Safe"
    elif score < 50:
        verdict = "Suspicious"
    else:
        verdict = "Malicious"

    return {
        "metadata": {
            "filename": filename,
            "extension": extension,
            "size_bytes": filesize
        },
        "analysis": {
            "sha256": sha,
            "yara_match": False,
            "static_score": score,
            "static_reasons": reasons,
            "verdict": verdict
        }
    }
