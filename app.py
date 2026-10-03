import json
import math
import secrets
import hashlib
import string
import time
import urllib.request
import urllib.error
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer

# ---------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------
PORT = 5000
MIN_LENGTH = 4
MAX_LENGTH = 128
AMBIGUOUS = set("0O1lI5S2Z8B")
RATE_LIMIT = 60
HIBP_API = "https://api.pwnedpasswords.com/range/"

CHAR_SETS = {
    "uppercase": string.ascii_uppercase,
    "lowercase": string.ascii_lowercase,
    "digits":    string.digits,
    "symbols":   string.punctuation,
}

# Built-in wordlist for passphrase mode (~200 words)
WORDS = [
    "amber","anchor","apple","arrow","autumn","beacon","bison","blade","breeze","bridge",
    "cabin","cactus","camera","candle","canyon","cedar","chisel","circle","clover","coast",
    "comet","copper","coral","cosmic","crane","crystal","dawn","delta","desert","dolphin",
    "dragon","eagle","ember","engine","falcon","feather","fern","flame","forest","fossil",
    "fox","galaxy","garden","glacier","globe","granite","harbor","hazel","helix","horizon",
    "island","ivory","jade","jasmine","jungle","kestrel","kite","lagoon","lantern","lark",
    "lava","legend","lemon","linen","lotus","lunar","maple","marble","meadow","meteor",
    "mist","moon","moss","mountain","nebula","nectar","ninja","noble","north","nova",
    "oasis","ocean","olive","onyx","opal","orbit","orchid","otter","oxide","palm",
    "panda","pearl","pebble","penguin","phoenix","pine","planet","plasma","plume","pond",
    "poppy","prism","pulse","quartz","quest","quiet","quill","raven","reef","rhino",
    "river","robin","rocket","rose","ruby","rustic","sage","sail","salmon","sapphire",
    "scarlet","shadow","shell","silver","sky","snow","solar","sparrow","spice","spiral",
    "spring","star","stone","storm","summit","sunset","swift","tiger","timber","topaz",
    "tower","trail","tulip","tundra","turtle","umber","valley","velvet","vertex","violet",
    "volcano","voyage","walnut","wave","whale","wheat","willow","wind","winter","wolf",
    "wonder","yarrow","zebra","zenith","zephyr","zinc","aurora","basalt","cobalt","dune",
    "echo","fjord","garnet","grove","harvest","inlet","jasper","kelp","lagoon","maple",
    "nimbus","ochre","petal","quartz","ripple","saffron","thistle","uplift","violet","wisp",
]

# ---------------------------------------------------------------
# RATE LIMITING
# ---------------------------------------------------------------
RATE_STORE = defaultdict(list)

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    RATE_STORE[ip] = [t for t in RATE_STORE[ip] if now - t < 60]
    if len(RATE_STORE[ip]) >= RATE_LIMIT:
        return True
    RATE_STORE[ip].append(now)
    return False

# ---------------------------------------------------------------
# AUDIT LOG (in-memory, last 200 events)
# ---------------------------------------------------------------
AUDIT_LOG = []

def log_event(event_type: str, **metadata):
    AUDIT_LOG.append({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event_type,
        **metadata,
    })
    if len(AUDIT_LOG) > 200:
        AUDIT_LOG.pop(0)

# ---------------------------------------------------------------
# PHASE 1: VALIDATION
# ---------------------------------------------------------------
def validate_input(data: dict, allow_bulk: bool = False) -> tuple:
    try:
        length = int(data.get("length", 0))
    except (TypeError, ValueError):
        return False, "Length must be an integer.", {}

    if length < MIN_LENGTH:
        return False, f"Length must be at least {MIN_LENGTH}.", {}
    if length > MAX_LENGTH:
        return False, f"Length cannot exceed {MAX_LENGTH}.", {}

    mode = data.get("mode", "random")
    if mode not in ("random", "passphrase"):
        return False, "Invalid mode.", {}

    types = [k for k in CHAR_SETS if data.get(k) is True]

    if mode == "random" and not types:
        return False, "Select at least one character type.", {}

    cleaned = {
        "length": length,
        "mode": mode,
        "types": types,
        "exclude_ambiguous": bool(data.get("exclude_ambiguous", False)),
        "no_repeat": bool(data.get("no_repeat", False)),
    }

    if allow_bulk:
        try:
            count = int(data.get("count", 1))
        except (TypeError, ValueError):
            return False, "Count must be an integer.", {}
        if not 1 <= count <= 100:
            return False, "Count must be between 1 and 100.", {}
        cleaned["count"] = count

    return True, "", cleaned

# ---------------------------------------------------------------
# PHASE 2: GENERATION
# ---------------------------------------------------------------
def build_pool(types: list, exclude_ambiguous: bool) -> str:
    pool = "".join(CHAR_SETS[t] for t in types)
    if exclude_ambiguous:
        pool = "".join(c for c in pool if c not in AMBIGUOUS)
    return pool

def generate_random_password(length: int, types: list,
                             exclude_ambiguous: bool = False,
                             no_repeat: bool = False) -> str:
    pool = build_pool(types, exclude_ambiguous)

    if no_repeat and length > len(pool):
        raise ValueError(f"Cannot generate {length} unique chars from a pool of {len(pool)}.")

    if no_repeat:
        chars = list(pool)
        secure_shuffle(chars)
        return "".join(chars[:length])

    guaranteed = []
    for t in types:
        tset = CHAR_SETS[t]
        if exclude_ambiguous:
            tset = "".join(c for c in tset if c not in AMBIGUOUS)
        if tset:
            guaranteed.append(secrets.choice(tset))

    remaining = [secrets.choice(pool) for _ in range(length - len(guaranteed))]
    combined = guaranteed + remaining
    secure_shuffle(combined)
    return "".join(combined)

def generate_passphrase(word_count: int = 4) -> str:
    words = [secrets.choice(WORDS) for _ in range(max(3, word_count))]
    words.append(str(secrets.randbelow(100)))
    return "-".join(words)

def secure_shuffle(lst: list) -> None:
    for i in range(len(lst) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        lst[i], lst[j] = lst[j], lst[i]

def generate_password(cleaned: dict) -> str:
    if cleaned["mode"] == "passphrase":
        return generate_passphrase(cleaned["length"])
    return generate_random_password(
        cleaned["length"], cleaned["types"],
        cleaned["exclude_ambiguous"], cleaned["no_repeat"],
    )

# ---------------------------------------------------------------
# PHASE 3: ENTROPY
# ---------------------------------------------------------------
def calc_entropy(cleaned: dict) -> float:
    if cleaned["mode"] == "passphrase":
        return round(cleaned["length"] * math.log2(len(WORDS)) + math.log2(100), 2)
    pool_size = len(build_pool(cleaned["types"], cleaned["exclude_ambiguous"]))
    if pool_size <= 1:
        return 0.0
    return round(cleaned["length"] * math.log2(pool_size), 2)

def classify_strength(entropy: float) -> str:
    if entropy < 40:  return "Weak"
    if entropy < 60:  return "Medium"
    if entropy < 90:  return "Strong"
    return "Very Strong"

# ---------------------------------------------------------------
# BACKUP CODES + API KEYS
# ---------------------------------------------------------------
def gen_backup_codes(n: int = 10) -> list:
    return [
        f"{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"
        for _ in range(n)
    ]

def gen_api_key() -> str:
    return f"sk_live_{secrets.token_urlsafe(32)}"

# ---------------------------------------------------------------
# BREACH CHECK (k-anonymity)
# ---------------------------------------------------------------
def check_breach(password: str) -> int:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        req = urllib.request.Request(
            HIBP_API + prefix,
            headers={"User-Agent": "PassGen-Ultimate/1.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")
        for line in body.splitlines():
            if line.startswith(suffix):
                return int(line.split(":")[1])
        return 0
    except (urllib.error.URLError, TimeoutError, ValueError):
        return -1

# ---------------------------------------------------------------
# HTTP HANDLER
# ---------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):

    def _cors(self, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.end_headers()

    def _json(self, status: int, payload: dict):
        self._cors(status)
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def _read_json(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n).decode("utf-8")
            return json.loads(body) if body else {}
        except (ValueError, json.JSONDecodeError):
            return {}

    def _rate_ok(self) -> bool:
        ip = self.client_address[0]
        if is_rate_limited(ip):
            self._json(429, {"error": "Rate limit exceeded. Try again in a minute."})
            return False
        return True

    def do_OPTIONS(self):
        self._cors(204)

    def do_GET(self):
        if self.path == "/":
            self._json(200, {
                "status": "online",
                "service": "Ultimate Password Generator",
                "endpoints": ["/generate", "/generate-bulk", "/backup-codes",
                              "/api-key", "/check-breach", "/audit"],
            })
        elif self.path == "/audit":
            self._json(200, {"events": AUDIT_LOG[-50:]})
        else:
            self._json(404, {"error": "Not found."})

    def do_POST(self):
        if not self._rate_ok():
            return

        routes = {
            "/generate":      self._handle_generate,
            "/generate-bulk": self._handle_bulk,
            "/backup-codes":  self._handle_backup,
            "/api-key":       self._handle_api_key,
            "/check-breach":  self._handle_breach,
        }
        handler = routes.get(self.path)
        if not handler:
            self._json(404, {"error": "Not found."})
            return
        handler()

    # ---------- ENDPOINT HANDLERS ----------
    def _handle_generate(self):
        data = self._read_json()
        ok, err, cleaned = validate_input(data)
        if not ok:
            self._json(400, {"error": err})
            return

        try:
            password = generate_password(cleaned)
        except ValueError as e:
            self._json(400, {"error": str(e)})
            return

        entropy = calc_entropy(cleaned)
        strength = classify_strength(entropy)

        log_event("generate",
                  mode=cleaned["mode"], length=cleaned["length"],
                  entropy=entropy, strength=strength)

        self._json(200, {
            "password": password,
            "length": cleaned["length"],
            "entropy": entropy,
            "strength": strength,
            "mode": cleaned["mode"],
        })

    def _handle_bulk(self):
        data = self._read_json()
        ok, err, cleaned = validate_input(data, allow_bulk=True)
        if not ok:
            self._json(400, {"error": err})
            return

        try:
            passwords = [generate_password(cleaned) for _ in range(cleaned["count"])]
        except ValueError as e:
            self._json(400, {"error": str(e)})
            return

        log_event("bulk", count=cleaned["count"], length=cleaned["length"])
        self._json(200, {"passwords": passwords, "count": len(passwords)})

    def _handle_backup(self):
        codes = gen_backup_codes(10)
        log_event("backup_codes", count=10)
        self._json(200, {"codes": codes})

    def _handle_api_key(self):
        key = gen_api_key()
        log_event("api_key")
        self._json(200, {"key": key})

    def _handle_breach(self):
        data = self._read_json()
        pw = data.get("password", "")
        if not pw:
            self._json(400, {"error": "Password required."})
            return
        count = check_breach(pw)
        if count == -1:
            self._json(503, {"error": "Breach API unreachable. Try again."})
            return
        log_event("breach_check", breached=count > 0)
        self._json(200, {"count": count, "breached": count > 0})

    def log_message(self, *args):
        pass

# ---------------------------------------------------------------
# BOOTSTRAP
# ---------------------------------------------------------------
def run():
    server = HTTPServer(("127.0.0.1", PORT), Handler)
    print("=" * 60)
    print("  🔐 Ultimate Password Generator — Backend Online")
    print("=" * 60)
    print(f"  URL:  http://127.0.0.1:{PORT}")
    print("  Endpoints:")
    print("    POST /generate         — single password")
    print("    POST /generate-bulk    — up to 100 passwords")
    print("    POST /backup-codes     — 10 one-time codes")
    print("    POST /api-key          — developer API key")
    print("    POST /check-breach     — HIBP k-anonymity check")
    print("    GET  /audit            — last 50 events (no plaintext)")
    print("=" * 60)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
        server.server_close()

if __name__ == "__main__":
    run()