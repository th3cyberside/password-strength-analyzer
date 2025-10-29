from flask import Flask, render_template, request, jsonify
import math, string, random, requests, hashlib, os

app = Flask(__name__)

# ---------- Load common passwords ----------
COMMON_PASSWORDS = set()
COMMON_PATH = os.path.join(os.path.dirname(__file__), "data", "common_passwords.txt")
if os.path.exists(COMMON_PATH):
    with open(COMMON_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            pwd = line.strip().lower()
            if pwd:
                COMMON_PASSWORDS.add(pwd)


# ---------- Helper functions ----------

def password_entropy(password):
    """Calculate entropy (bits) based on character variety and length."""
    if not password:
        return 0

    charset = 0
    lowers = uppers = digits = symbols = False

    for c in password:
        if c.islower():
            lowers = True
        elif c.isupper():
            uppers = True
        elif c.isdigit():
            digits = True
        else:
            symbols = True

    if lowers:
        charset += 26
    if uppers:
        charset += 26
    if digits:
        charset += 10
    if symbols:
        charset += 32

    entropy = len(password) * math.log2(charset) if charset else 0
    return round(entropy, 2)


def rate_password(entropy):
    """Rate based on entropy bits."""
    if entropy < 28:
        return "Very Weak"
    elif entropy < 36:
        return "Weak"
    elif entropy < 60:
        return "Reasonable"
    elif entropy < 128:
        return "Strong"
    else:
        return "Very Strong"


def contains_common_substring(s):
    """Detects if password contains a common pattern (ignore short ones)."""
    low = s.lower()
    for pwd in COMMON_PASSWORDS:
        if len(pwd) < 4:
            continue  # ignore very short ones like "0", "12", etc.
        if pwd in low:
            return pwd
    return None


# ---------- Password generator ----------

def generate_password(length=16, upper=True, digits=True, symbols=True):
    charset = string.ascii_lowercase
    if upper:
        charset += string.ascii_uppercase
    if digits:
        charset += string.digits
    if symbols:
        charset += "!@#$%^&*()-_=+[]{};:,.<>?"

    if length < 4:
        length = 4

    return "".join(random.choice(charset) for _ in range(length))


# ---------- API endpoints ----------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze_password():
    data = request.get_json()
    pwd = data.get("password", "")
    if not pwd:
        return jsonify({"error": "Missing password"}), 400

    entropy = password_entropy(pwd)
    rating = rate_password(entropy)
    suggestions = []

    # Common pattern check
    common_sub = contains_common_substring(pwd)
    if common_sub:
        suggestions.append(
            f"Your password includes a very common pattern ('{common_sub}'). Try avoiding it."
        )

    # Composition checks
    if len(pwd) < 8:
        suggestions.append("Use at least 8 characters.")
    if not any(c.islower() for c in pwd):
        suggestions.append("Add lowercase letters.")
    if not any(c.isupper() for c in pwd):
        suggestions.append("Add uppercase letters.")
    if not any(c.isdigit() for c in pwd):
        suggestions.append("Add some numbers.")
    if not any(not c.isalnum() for c in pwd):
        suggestions.append("Add special symbols for more strength.")

    return jsonify({
        "length": len(pwd),
        "entropy": entropy,
        "rating": rating,
        "is_common": bool(common_sub),
        "suggestions": suggestions
    })


@app.route("/api/generate")
def generate_api():
    try:
        length = int(request.args.get("length", 16))
    except ValueError:
        length = 16

    upper = request.args.get("upper", "true").lower() == "true"
    digits = request.args.get("digits", "true").lower() == "true"
    symbols = request.args.get("symbols", "true").lower() == "true"

    pwd = generate_password(length, upper, digits, symbols)
    return jsonify({"password": pwd})


@app.route("/api/pwned", methods=["POST"])
def check_pwned():
    """Use k-anonymity (Have I Been Pwned API)."""
    data = request.get_json()
    pwd = data.get("password", "")
    if not pwd:
        return jsonify({"error": "Missing password"}), 400

    sha1 = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        resp = requests.get(url, timeout=5)
        if resp.status_code != 200:
            return jsonify({"error": "HIBP API error"}), 502

        hashes = (line.split(":") for line in resp.text.splitlines())
        count = 0
        for h, c in hashes:
            if h == suffix:
                count = int(c)
                break

        return jsonify({"pwned_count": count})

    except requests.RequestException:
        return jsonify({"error": "Network error"}), 500


# ---------- Run ----------
if __name__ == "__main__":
    app.run(debug=True)
