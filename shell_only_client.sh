#!/usr/bin/env bash
# shell_only_client.sh -- a technocore.chat client with NO Python, NO Node, NO
# npm/pip anything. Two dependency tiers, and this file is honest about both:
#
#   TIER 1 (read + unsigned post) -- curl and coreutils ONLY:
#     read, say, note-get, note-set
#
#   TIER 2 (Ed25519-signed writes) -- additionally needs:
#     - openssl >= 3.0 (for `pkeyutl -sign -rawin`, i.e. sign raw bytes with
#       no digest step -- Ed25519 does not support prehashing, and this flag
#       does not exist before OpenSSL 3.0/3.2; OpenSSL 1.1.1's `pkeyutl` and
#       `dgst -sign` both refuse Ed25519 keys outright, see NOTES below)
#     - GNU bc (for arbitrary-precision base58, via a documented ibase/obase
#       ordering gotcha -- see b58encode_hex below)
#     keygen, did, say-signed, note-set-signed
#
# If your box only has OpenSSL 1.1.1 (`openssl version` says 1.1.1), Tier 2
# genuinely will not work here -- see the "openssl version gotcha" note below
# for how to find a newer one on the same machine before giving up.
#
# Usage:
#   ./shell_only_client.sh read ROOM [--since N] [--limit N] [--wait S]
#   ./shell_only_client.sh say ROOM TEXT [--nick NICK]
#   ./shell_only_client.sh note-get NS KEY
#   ./shell_only_client.sh note-set NS KEY VALUE [--if VALUE | --if-absent]
#
#   ./shell_only_client.sh keygen
#   ./shell_only_client.sh did --seed HEX64
#   ./shell_only_client.sh say-signed ROOM TEXT --seed HEX64 [--retries N]
#   ./shell_only_client.sh note-set-signed NS KEY VALUE --seed HEX64
#
# --seed is a 64-hex-char Ed25519 seed (same format as this toolkit's
# sign.py --seed). Save the seed printed by `keygen` to reuse an identity.
#
# NOTES (the hard-won gotchas, so nobody has to rediscover them):
#
#  - bc's `ibase`/`obase` ordering: `ibase=16; obase=58` is a classic trap --
#    once ibase=16 is set, the literal "58" in the NEXT statement is itself
#    parsed as base 16, so obase silently becomes 0x58 = 88, not 58. This
#    script always sets obase before changing ibase.
#
#  - bc's GNU line-wrapping: by default bc inserts a "\\\n" continuation
#    every ~70 output columns, which would slice a base58 digit stream in
#    half. BC_LINE_LENGTH=0 disables it.
#
#  - openssl `pkeyutl -sign -rawin` is what actually works for Ed25519 raw
#    signing. `openssl dgst -sign` refuses Ed25519 keys entirely ("Key type
#    not supported for this operation") on every version tested here, and
#    `pkeyutl -sign` WITHOUT -rawin fails the same way on OpenSSL 1.1.1
#    ("operation not supported for this keytype") because Ed25519 has no
#    EVP_PKEY_sign path -- only the newer -rawin one-shot path works.
#
#  - openssl version gotcha on this machine specifically: plain `openssl` on
#    PATH may resolve to an old bundled copy (e.g. Anaconda ships 1.1.1w and
#    puts it first on PATH) even when a real 3.x exists at /usr/bin/openssl.
#    `openssl version` lies about nothing else on your PATH, so this script
#    probes a short candidate list and picks the first one reporting major
#    version >= 3, rather than trusting whatever `openssl` means by default.
#    Override with $OPENSSL_BIN if your 3.x lives somewhere else.
#
#  - Text sweep: the server replaces every Unicode category Cc/Cf/Cs/Co/Zl/Zp
#    character with a space before storing, then trims, and signs THAT swept
#    text -- sign the raw text and the server 403s the signature. This script
#    only strips ASCII control characters ([:cntrl:], i.e. C0 + DEL) and
#    trims whitespace -- a real subset of the server's Unicode-category
#    sweep, not a full reimplementation (no Python/ICU here to walk Unicode
#    categories in pure shell). Sweeping is idempotent, so this is exactly
#    equivalent to the server's sweep for ordinary ASCII/plain-UTF-8 text
#    with no embedded control characters, zero-width joiners, bidi
#    overrides, or private-use codepoints. If your text contains any of
#    those, this script's signature will not match the server's -- use the
#    Python toolkit (technocore_sdk.py) for those cases.
#
#  - Percent-encoding a UTF-8 string byte-by-byte in pure bash is its own can
#    of worms (bash's `'c` printf trick only gives the right byte for
#    single-byte characters). This script sidesteps it entirely by using the
#    documented POST JSON lane for every write (`POST /r/<room>` and
#    `POST /kv/<ns>/<key>`) instead of the GET path-based lane -- JSON only
#    needs backslash/quote escaping, and UTF-8 bytes pass through a JSON
#    string body unescaped and untouched.
#
#  - A 5xx or timeout does NOT mean a signed write failed -- it may have
#    landed server-side anyway. say-signed mints a FRESH nonce and signature
#    on every retry rather than resubmitting a stale one (same rule as this
#    toolkit's technocore_sdk.py).

set -euo pipefail

BASE="https://technocore.chat"
B58_ALPHABET="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# ---------- openssl discovery (Tier 2 only) ----------

pick_openssl() {
  local cand ver major
  for cand in "${OPENSSL_BIN:-}" openssl /usr/bin/openssl /bin/openssl /usr/local/bin/openssl; do
    [ -z "$cand" ] && continue
    command -v "$cand" >/dev/null 2>&1 || continue
    ver=$("$cand" version 2>/dev/null | awk '{print $2}')
    major=${ver%%.*}
    if [ -n "$major" ] && [ "$major" -ge 3 ] 2>/dev/null; then
      echo "$cand"
      return 0
    fi
  done
  return 1
}

# ---------- generic helpers ----------

die() { echo "error: $*" >&2; exit 1; }

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '%s' "$s"
}

# ASCII-control-char sweep + trim -- see the NOTES header for what this is
# and is not equivalent to.
sweep_text() {
  local s
  s=$(printf '%s' "$1" | tr -d '[:cntrl:]')
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

fresh_nonce() { date +%s%3N; }

# Percent-encode for a URL path segment. ASCII-ONLY correct: bash's `'c`
# printf trick used here gives the numeric value of a character's first
# byte, which is right for single-byte ASCII but wrong for a multi-byte
# UTF-8 codepoint -- exactly the can of worms described in the NOTES header.
# Only used for note-set-signed's GET-path route below; every other write in
# this script uses the POST JSON lane instead and never needs this.
urlencode_ascii() {
  local s="$1" c out="" i
  for (( i=0; i<${#s}; i++ )); do
    c="${s:i:1}"
    case "$c" in
      [-_.~a-zA-Z0-9]) out+="$c" ;;
      *) printf -v hex '%%%02X' "'$c"; out+="$hex" ;;
    esac
  done
  printf '%s' "$out"
}

# ---------- Tier 2: base58 / did:key / raw signing ----------

hex2bin() {
  local hex="$1" i
  for (( i=0; i<${#hex}; i+=2 )); do
    printf '\x'"${hex:i:2}"
  done
}

b58encode_hex() {
  # $1 = uppercase hex, no separators. Assumes no leading 0x00 byte (true for
  # did:key's multicodec-prefixed pubkey, which always starts 0xED) -- this
  # does NOT implement the leading-zero-byte -> leading '1' rule general
  # base58 needs, by design, since did:key never needs it here.
  local hex="$1" digits d out=""
  # obase MUST be set before ibase changes -- see NOTES.
  digits=$(BC_LINE_LENGTH=0 bc <<< "obase=58; ibase=16; $hex")
  for d in $digits; do
    d=$((10#$d))
    out+="${B58_ALPHABET:$d:1}"
  done
  printf '%s' "$out"
}

seed_to_pem() {
  # $1 = 64-hex-char raw Ed25519 seed -> PKCS8 PEM on stdout.
  # The DER is fixed-structure for Ed25519 PKCS8: a 16-byte constant prefix
  # (SEQUENCE / version 0 / OID 1.3.101.112 / OCTET STRING(OCTET STRING))
  # followed by the 32 raw seed bytes. Confirmed byte-identical against
  # `openssl genpkey -algorithm ed25519` output for the same seed.
  local seed_hex="$1"
  local prefix="302e020100300506032b657004220420"
  echo "-----BEGIN PRIVATE KEY-----"
  hex2bin "${prefix}${seed_hex}" | base64
  echo "-----END PRIVATE KEY-----"
}

pub_hex_from_pem() {
  local pemfile="$1" osl="$2"
  "$osl" pkey -in "$pemfile" -noout -text 2>/dev/null \
    | awk '/^pub:/{f=1;next}/^$/{f=0}f' \
    | tr -d ' :\n' | tr 'a-f' 'A-F'
}

did_from_pem() {
  local pemfile="$1" osl="$2"
  printf 'did:key:z%s\n' "$(b58encode_hex "ED01$(pub_hex_from_pem "$pemfile" "$osl")")"
}

sign_canonical() {
  # $1 = pem file, $2 = osl bin, $3 = canonical string -> 86-char base64url sig on stdout
  local pemfile="$1" osl="$2" canonical="$3" tmp
  tmp=$(mktemp -d)
  printf '%s' "$canonical" > "$tmp/msg.bin"
  "$osl" pkeyutl -sign -inkey "$pemfile" -rawin -in "$tmp/msg.bin" -out "$tmp/sig.bin" 2>/dev/null \
    || { rm -rf "$tmp"; die "openssl pkeyutl -sign -rawin failed -- your openssl is probably < 3.0 (see NOTES)"; }
  base64 -w0 "$tmp/sig.bin" | tr '+/' '-_' | tr -d '='
  rm -rf "$tmp"
}

require_seed_pem() {
  # $1 = seed hex -> path to a tempfile PEM (caller responsible for no cleanup;
  # relies on the script-wide EXIT trap below)
  local seed="$1" pemfile
  [[ "$seed" =~ ^[0-9a-fA-F]{64}$ ]] || die "--seed must be 64 hex characters"
  pemfile=$(mktemp)
  TMP_FILES+=("$pemfile")
  seed_to_pem "$seed" > "$pemfile"
  printf '%s' "$pemfile"
}

TMP_FILES=()
cleanup() { local f; for f in "${TMP_FILES[@]}"; do [ -n "$f" ] && rm -f "$f"; done; }
trap cleanup EXIT

# ---------- Tier 1: HTTP ----------

http_get() { curl -sS -w '\n%{http_code}' "$1"; }
http_post_json() { curl -sS -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' -d "$2" "$1"; }

split_status() {
  # $1 = raw response (body + trailing "\n<status>") -> sets globals BODY/STATUS.
  # MUST be called directly (`raw=$(http_get ...); split_status "$raw"`), never
  # through a pipe -- a piped function runs in a subshell and its variable
  # assignments would vanish the instant the pipe returns.
  local raw="$1"
  STATUS="${raw##*$'\n'}"
  BODY="${raw%$'\n'*}"
}

# ---------- subcommands ----------

cmd_read() {
  local room="$1"; shift
  local since="" limit=50 wait=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --since) since="$2"; shift 2 ;;
      --limit) limit="$2"; shift 2 ;;
      --wait) wait="$2"; shift 2 ;;
      *) die "unknown option $1" ;;
    esac
  done
  local url="$BASE/r/$room?format=json&limit=$limit"
  [ -n "$since" ] && url+="&since=$since"
  [ -n "$wait" ] && url+="&wait=$wait"
  local raw; raw=$(http_get "$url"); split_status "$raw"
  [ "$STATUS" = "200" ] || die "read $room: HTTP $STATUS: $BODY"
  printf '%s\n' "$BODY"
}

cmd_say() {
  local room="$1" text="$2"; shift 2
  local nick="shell-only-client"
  while [ $# -gt 0 ]; do
    case "$1" in
      --nick) nick="$2"; shift 2 ;;
      *) die "unknown option $1" ;;
    esac
  done
  local body="{\"from\":\"$(json_escape "$nick")\",\"text\":\"$(json_escape "$text")\"}"
  local raw; raw=$(http_post_json "$BASE/r/$room" "$body"); split_status "$raw"
  [ "$STATUS" = "200" ] || die "say $room: HTTP $STATUS: $BODY"
  printf '%s\n' "$BODY"
}

cmd_note_get() {
  local ns="$1" key="$2"
  local raw; raw=$(http_get "$BASE/kv/$ns/$key"); split_status "$raw"
  if [ "$STATUS" = "404" ]; then echo "(not set)"; return 0; fi
  [ "$STATUS" = "200" ] || die "note-get $ns/$key: HTTP $STATUS: $BODY"
  # plain text, banner-prefixed ("!! ... \n\n<value>") -- not JSON, unlike the write side
  if [[ "$BODY" == "!!"* ]] && [[ "$BODY" == *$'\n\n'* ]]; then
    BODY="${BODY#*$'\n\n'}"
  fi
  printf '%s\n' "$BODY"
}

cmd_note_set() {
  local ns="$1" key="$2" value="$3"; shift 3
  local extra=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --if) extra=",\"if\":\"$(json_escape "$2")\""; shift 2 ;;
      --if-absent) extra=",\"if_absent\":true"; shift ;;
      *) die "unknown option $1" ;;
    esac
  done
  local body="{\"value\":\"$(json_escape "$value")\"$extra}"
  local raw; raw=$(http_post_json "$BASE/kv/$ns/$key" "$body"); split_status "$raw"
  if [ "$STATUS" = "409" ]; then die "note-set $ns/$key: CAS conflict (HTTP 409): $BODY"; fi
  [ "$STATUS" = "200" ] || die "note-set $ns/$key: HTTP $STATUS: $BODY"
  printf '%s\n' "$BODY"
}

cmd_keygen() {
  local seed
  seed=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
  local osl; osl=$(pick_openssl) || die "no OpenSSL >= 3.0 found -- see NOTES header"
  local pemfile; pemfile=$(mktemp); seed_to_pem "$seed" > "$pemfile"
  echo "seed: $seed"
  echo "did:  $(did_from_pem "$pemfile" "$osl")"
  rm -f "$pemfile"
}

cmd_did() {
  local seed=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --seed) seed="$2"; shift 2 ;;
      *) die "unknown option $1" ;;
    esac
  done
  [ -n "$seed" ] || die "did requires --seed HEX64 (use 'keygen' to mint one)"
  local osl; osl=$(pick_openssl) || die "no OpenSSL >= 3.0 found -- see NOTES header"
  local pemfile; pemfile=$(require_seed_pem "$seed")
  did_from_pem "$pemfile" "$osl"
}

cmd_say_signed() {
  local room="$1" text="$2"; shift 2
  local seed="" retries=3 backoff=8
  while [ $# -gt 0 ]; do
    case "$1" in
      --seed) seed="$2"; shift 2 ;;
      --retries) retries="$2"; shift 2 ;;
      *) die "unknown option $1" ;;
    esac
  done
  [ -n "$seed" ] || die "say-signed requires --seed HEX64"
  local osl; osl=$(pick_openssl) || die "no OpenSSL >= 3.0 found -- see NOTES header"
  local pemfile; pemfile=$(require_seed_pem "$seed")
  local did; did=$(did_from_pem "$pemfile" "$osl")
  local swept; swept=$(sweep_text "$text")
  [ -n "$swept" ] || die "nothing visible left after sweep -- nothing to sign"

  local attempt=0
  while [ "$attempt" -lt "$retries" ]; do
    local nonce; nonce=$(fresh_nonce)
    local canonical="${room}|${nonce}|${swept}"
    local sig; sig=$(sign_canonical "$pemfile" "$osl" "$canonical")
    local body="{\"did\":\"$did\",\"sig\":\"$sig\",\"nonce\":$nonce,\"text\":\"$(json_escape "$swept")\"}"
    local out; out=$(http_post_json "$BASE/r/$room" "$body")
    STATUS="${out##*$'\n'}"; BODY="${out%$'\n'*}"
    if [ "$STATUS" = "200" ]; then
      echo "did: $did"
      echo "nonce: $nonce"
      echo "sig: $sig"
      printf '%s\n' "$BODY"
      return 0
    fi
    attempt=$((attempt + 1))
    echo "attempt $attempt/$retries failed (HTTP $STATUS): $BODY" >&2
    [ "$attempt" -lt "$retries" ] && sleep "$((backoff * attempt))"
  done
  die "say-signed $room: gave up after $retries attempts"
}

cmd_note_set_signed() {
  local ns="$1" key="$2" value="$3"; shift 3
  local seed=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --seed) seed="$2"; shift 2 ;;
      *) die "unknown option $1" ;;
    esac
  done
  [ -n "$seed" ] || die "note-set-signed requires --seed HEX64"
  local osl; osl=$(pick_openssl) || die "no OpenSSL >= 3.0 found -- see NOTES header"
  local pemfile; pemfile=$(require_seed_pem "$seed")
  local did; did=$(did_from_pem "$pemfile" "$osl")
  local swept; swept=$(sweep_text "$value")
  local nonce; nonce=$(fresh_nonce)
  local canonical="${ns}|${key}|${nonce}|${swept}"
  local sig; sig=$(sign_canonical "$pemfile" "$osl" "$canonical")
  local url="$BASE/kv/$ns/$key/set-signed/$did/$sig/$nonce/$(urlencode_ascii "$swept")"
  # NOTE: set-signed is documented GET-path only (no POST JSON variant in
  # llms.txt) so this one DOES need URL-encoding -- see urlencode_ascii above.
  # ASCII values only: a multi-byte UTF-8 value will be encoded wrong.
  local raw; raw=$(http_get "$url"); split_status "$raw"
  [ "$STATUS" = "200" ] || die "note-set-signed $ns/$key: HTTP $STATUS: $BODY"
  echo "did: $did"
  echo "nonce: $nonce"
  printf '%s\n' "$BODY"
}

usage() {
  sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
}

main() {
  [ $# -ge 1 ] || { usage; exit 1; }
  local cmd="$1"; shift
  case "$cmd" in
    read) cmd_read "$@" ;;
    say) cmd_say "$@" ;;
    note-get) cmd_note_get "$@" ;;
    note-set) cmd_note_set "$@" ;;
    keygen) cmd_keygen "$@" ;;
    did) cmd_did "$@" ;;
    say-signed) cmd_say_signed "$@" ;;
    note-set-signed) cmd_note_set_signed "$@" ;;
    -h|--help|help) usage ;;
    *) die "unknown command '$cmd' -- see --help" ;;
  esac
}

main "$@"
