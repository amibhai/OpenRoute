#!/usr/bin/env bash
# OpenRoute server: turns a Linux VPS into a hardened sing-box server for the
# OpenRoute extension (or any sing-box / Xray-compatible client) and prints
# the share links to paste into it.
#
#   sudo bash install-server.sh              install, or upgrade in place keeping your links
#   sudo bash install-server.sh show         print the links (and QR codes) again
#   sudo bash install-server.sh rotate       new credentials; the old links stop working
#   sudo bash install-server.sh doctor       check the server and explain anything wrong
#   sudo bash install-server.sh uninstall    remove it (--purge: sing-box too)
#        bash install-server.sh generate --dir DIR --host ADDR
#                                            only write a config + links into DIR
#
#   bash install-server.sh --help            every option
#
# Read it before running it as root; it's written to be read. server/README.md
# explains what it sets up and why. Everything runs from `main` on the last
# line, so a download cut short (curl … | sudo bash) runs nothing.
set -Eeuo pipefail
umask 022
export LC_ALL=C

readonly SCRIPT_VERSION=1.0.0
readonly SB_MIN=1.12.0            # oldest sing-box that reads the config this writes
readonly SB_PIN=1.14.4            # the release --source release installs
readonly SS_METHOD=2022-blake3-aes-128-gcm
readonly SVC=openroute-server
readonly SVC_USER=openroute
readonly REPO_URL=https://github.com/amibhai/OpenRoute
# Reality borrows one of these sites' TLS handshakes. All are huge, serve
# TLS 1.3 + HTTP/2, and are reachable from the networks OpenRoute is for;
# "auto" takes whichever answers this server fastest.
readonly SNI_CANDIDATES="www.microsoft.com www.apple.com www.amazon.com www.samsung.com www.nvidia.com addons.mozilla.org dl.google.com"
# The key that signs SagerNet's apt and rpm repositories (embedded at the
# bottom, so nothing is fetched to decide what to trust).
readonly SAGERNET_FPR=2C317FBD5D886B4E89BAE8DA6D9152172A2B2F0C
# Destinations clients may never reach through the server: the box itself,
# its LAN, cloud metadata services (169.254.169.254, Alibaba's
# 100.100.100.200) and other non-public ranges. ip_is_private covers
# RFC 1918 and ULA; these are the rest.
readonly BLOCKED_CIDRS='"0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "198.18.0.0/15", "224.0.0.0/3", "::/127", "fe80::/10", "fc00::/7", "ff00::/8"'

# sha256 of sing-box-$SB_PIN-linux-<arch>.tar.gz, from the GitHub release.
sb_pin_sha256() {
  case $1 in
    amd64) echo 699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968 ;;
    arm64) echo 436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26 ;;
    armv7) echo fd164ed45ebc784f657a3e1d0e0ad0f68afdcff864ee57122c2cfed3ddb80a00 ;;
    386) echo efb46daaa48ee55e090bd1dfcaee34bfbe9bdbd9b89fa9f328d25f81a619e865 ;;
    *) return 1 ;;
  esac
}

# Every system path hangs off $OPENROUTE_ROOT so the test suite can run the
# real flow against a scratch directory, with stand-ins for systemctl & co.
ROOT=${OPENROUTE_ROOT:-}
PROC=$ROOT/proc
UNIT_FILE=$ROOT/etc/systemd/system/$SVC.service
SYSCTL_FILE=$ROOT/etc/sysctl.d/90-$SVC.conf
STATE_DIR=$ROOT/var/lib/$SVC
LEGACY_ENV=$ROOT/etc/sing-box/openroute.env       # where v0.3 kept things
LEGACY_CONFIG=$ROOT/etc/sing-box/config.json
APT_LIST=$ROOT/etc/apt/sources.list.d/openroute-sagernet.sources
APT_KEY=$ROOT/etc/apt/keyrings/openroute-sagernet.asc
RPM_REPO=$ROOT/etc/yum.repos.d/openroute-sagernet.repo
RPM_KEY=$ROOT/etc/pki/rpm-gpg/RPM-GPG-KEY-openroute-sagernet

set_conf_dir() {
  CONF_DIR=$1
  STATE_FILE=$CONF_DIR/state.env
  CONFIG=$CONF_DIR/config.json
  LINKS_FILE=$CONF_DIR/links.txt
  HY2_CERT=$CONF_DIR/hysteria2.crt
  HY2_KEY=$CONF_DIR/hysteria2.key
}
set_conf_dir "$ROOT/etc/$SVC"

# v0.3 took these from the environment; they still work.
ENV_SNI=${REALITY_SNI:-}
ENV_HOST=${SERVER_IP:-}
ENV_VLESS_PORT=${VLESS_PORT:-}
ENV_SS_PORT=${SS_PORT:-}

# ---- output -----------------------------------------------------------------

if [ -t 1 ] && [ -t 2 ]; then
  BOLD=$'\e[1m' GREEN=$'\e[32m' YELLOW=$'\e[33m' RED=$'\e[31m' OFF=$'\e[0m'
else
  BOLD='' GREEN='' YELLOW='' RED='' OFF=''
fi
say() { printf '%s\n' "$*"; }
step() { printf '\n%s==> %s%s\n' "$BOLD" "$*" "$OFF"; }
ok() { printf '  %s✓%s %s\n' "$GREEN" "$OFF" "$*"; }
note() { printf '  · %s\n' "$*"; }
warn() { printf '  %s!%s %s\n' "$YELLOW" "$OFF" "$*" >&2; }
die() { printf '%serror:%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

on_error() {
  # Only the top-level shell reports, so a failure inside $(…) isn't printed twice.
  [ "${BASHPID:-$$}" = "$$" ] || return 0
  printf '%serror:%s unexpected failure at line %s (exit %s): %s\nPlease report it: %s/issues\n' \
    "$RED" "$OFF" "$1" "$2" "$3" "$REPO_URL" >&2
}
trap 'on_error "$LINENO" "$?" "$BASH_COMMAND"' ERR

usage() {
  cat <<EOF
OpenRoute server $SCRIPT_VERSION: a hardened sing-box server for the OpenRoute extension.

Usage: sudo bash install-server.sh [command] [options]

Commands
  install      Install, or upgrade in place keeping your credentials (default)
  show         Print the share links and QR codes again
  rotate       Issue new credentials; the old links stop working
  doctor       Check the server and explain anything that's wrong
  uninstall    Remove the service, its config and its firewall rules
  generate     Write config.json + links into --dir and change nothing else

Options
  --sni HOST|auto     Site Reality impersonates (default: auto, the fastest of
                      several big sites that pass a TLS 1.3 + HTTP/2 check)
  --host ADDR         Address put in the links (default: this server's public
                      IP; a domain name pointing here works too)
  --vless-port N      VLESS-Reality port, TCP (default 443)
  --ss-port N         Shadowsocks-2022 port, TCP+UDP (default: random 20000-39999)
  --hysteria2         Also offer Hysteria2 (QUIC over UDP) with a pinned
                      self-signed certificate; --no-hysteria2 removes it
  --hy2-port N        Hysteria2 port, UDP (default: random 20000-39999)
  --new-ports         With rotate: move the Shadowsocks and Hysteria2 ports too
  --name NAME         Label shown in client apps (default OpenRoute)
  --source repo|release|existing
                      Where sing-box comes from: SagerNet's signed package
                      repository (default on apt/dnf systems), the pinned
                      $SB_PIN release checked against a built-in SHA-256, or
                      the one already installed
  --no-firewall       Leave ufw / firewalld / iptables alone
  --no-bbr            Don't enable BBR congestion control
  --no-qr             Don't print QR codes
  --purge             With uninstall: also remove sing-box, if this installed it
  --yes               Don't ask for confirmation
  --skip-sni-check    Use --sni as given without testing it
  --sing-box PATH     Use this sing-box binary
  --dir DIR           With generate: where to write (required)
  --listen ADDR       Listen address (default :: with IPv6, else 0.0.0.0)
  --reality-dest H:P  Where Reality relays handshakes (default: the --sni site, port 443)

v0.3's environment variables still work: REALITY_SNI, SERVER_IP, VLESS_PORT, SS_PORT.
Docs: $REPO_URL/tree/main/server
EOF
}

# ---- options ------------------------------------------------------------------

CMD=install
SYSTEM_MODE=1
OPT_SNI='' OPT_HOST='' OPT_VLESS_PORT='' OPT_SS_PORT='' OPT_HY2_PORT='' OPT_HY2=''
OPT_NEW_PORTS=0 OPT_NAME='' OPT_SOURCE='' OPT_FIREWALL=1 OPT_BBR=1 OPT_QR=1
OPT_PURGE=0 OPT_YES=0 OPT_SKIP_SNI=0 OPT_SINGBOX='' OPT_DIR='' OPT_LISTEN=''
OPT_DEST='' OPT_DEST_HOST='' OPT_DEST_PORT=''

parse_args() {
  OPT_SNI=$ENV_SNI OPT_HOST=$ENV_HOST OPT_VLESS_PORT=$ENV_VLESS_PORT OPT_SS_PORT=$ENV_SS_PORT
  if [ $# -gt 0 ]; then
    case $1 in
      install | show | rotate | doctor | uninstall | generate) CMD=$1; shift ;;
      --show) CMD=show; shift ;; # v0.3 spelling
      help | -h | --help) usage; exit 0 ;;
    esac
  fi
  while [ $# -gt 0 ]; do
    case $1 in
      --sni | --host | --vless-port | --ss-port | --hy2-port | --name | --source | --sing-box | --dir | --listen | --reality-dest)
        [ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value"
        case $1 in
          --sni) OPT_SNI=$2 ;;
          --host) OPT_HOST=$2 ;;
          --vless-port) OPT_VLESS_PORT=$2 ;;
          --ss-port) OPT_SS_PORT=$2 ;;
          --hy2-port) OPT_HY2_PORT=$2 ;;
          --name) OPT_NAME=$2 ;;
          --source) OPT_SOURCE=$2 ;;
          --sing-box) OPT_SINGBOX=$2 ;;
          --dir) OPT_DIR=$2 ;;
          --listen) OPT_LISTEN=$2 ;;
          --reality-dest) OPT_DEST=$2 ;;
        esac
        shift 2
        ;;
      --hysteria2) OPT_HY2=1; shift ;;
      --no-hysteria2) OPT_HY2=0; shift ;;
      --new-ports) OPT_NEW_PORTS=1; shift ;;
      --no-firewall) OPT_FIREWALL=0; shift ;;
      --no-bbr) OPT_BBR=0; shift ;;
      --no-qr) OPT_QR=0; shift ;;
      --purge) OPT_PURGE=1; shift ;;
      --yes | -y) OPT_YES=1; shift ;;
      --skip-sni-check) OPT_SKIP_SNI=1; shift ;;
      -h | --help) usage; exit 0 ;;
      *) die "unknown option: $1 (see --help)" ;;
    esac
  done

  local p
  for p in VLESS_PORT SS_PORT HY2_PORT; do
    local v="OPT_$p"
    [ -z "${!v}" ] || is_port "${!v}" || die "${p//_/ } must be a port number (1-65535), not: ${!v}"
  done
  [ -z "$OPT_SNI" ] || [ "$OPT_SNI" = auto ] || is_hostname "$OPT_SNI" || die "--sni must be a hostname, not: $OPT_SNI"
  [ -z "$OPT_HOST" ] || is_host "$OPT_HOST" || die "--host must be an IP address or a hostname, not: $OPT_HOST"
  [ -z "$OPT_NAME" ] || [[ $OPT_NAME =~ ^[A-Za-z0-9._\ -]{1,32}$ ]] || die "--name: up to 32 letters, digits, spaces, dots, dashes or underscores"
  case $OPT_SOURCE in '' | repo | release | existing) ;; *) die "--source must be repo, release or existing" ;; esac
  [ -z "$OPT_LISTEN" ] || is_ipv4 "$OPT_LISTEN" || is_ipv6 "$OPT_LISTEN" || die "--listen must be an IP address"
  [ -z "$OPT_DEST" ] || parse_dest "$OPT_DEST" || die "--reality-dest must be host:port (IPv6 as [addr]:port)"
}

# ---- small helpers ---------------------------------------------------------------

is_port() { [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && (($1 <= 65535)); }
is_ipv4() {
  local re='^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
  [[ $1 =~ $re ]]
}
is_ipv6() { [[ $1 == *:* && ${#1} -le 45 && $1 =~ ^[0-9A-Fa-f:.]+$ ]]; }
is_hostname() {
  local re='^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'
  [[ ${#1} -le 253 && $1 =~ $re ]]
}
is_host() { is_ipv4 "$1" || is_ipv6 "$1" || is_hostname "$1"; }

# SHA-256 of stdin, as hex: coreutils' sha256sum, or shasum where that's
# missing (macOS, for the generate step).
sha256_hex() {
  if have sha256sum; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}

parse_dest() {
  local d=$1 h p
  case $d in
    \[*\]:*) h=${d%]:*}; h=${h#[}; p=${d##*]:} ;;
    *:*) h=${d%:*}; p=${d##*:}; [[ $h != *:* ]] || return 1 ;;
    *) return 1 ;;
  esac
  is_host "$h" && is_port "$p" || return 1
  OPT_DEST_HOST=$h OPT_DEST_PORT=$p
}

urlencode() {
  local s=$1 out='' c i
  for ((i = 0; i < ${#s}; i++)); do
    c=${s:i:1}
    case $c in
      [A-Za-z0-9._~-]) out+=$c ;;
      *) printf -v c '%%%02X' "'$c"; out+=$c ;;
    esac
  done
  printf '%s' "$out"
}
link_host() { if [[ $1 == *:* ]]; then printf '[%s]' "$1"; else printf '%s' "$1"; fi; }
json_str() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; printf '"%s"' "$s"; }
clean_log() { printf '%s' "$1" | tr -d '\r' | sed 's/\x1b\[[0-9;]*m//g' | tail -n 3; }

need_root() { [ "$(id -u)" = 0 ] || die "this needs root: sudo bash install-server.sh $CMD"; }
need_systemd() {
  [ -d "$ROOT/run/systemd/system" ] || die "this needs a Linux with systemd (Debian, Ubuntu, Fedora, RHEL / Alma / Rocky, …)"
}
lock() {
  have flock || return 0
  mkdir -p "$ROOT/run"
  exec 9>"$ROOT/run/$SVC.lock"
  flock -n 9 || die "another install-server.sh is already running"
}

# ---- state ----------------------------------------------------------------------

readonly STATE_KEYS="FORMAT NAME HOST HOST_AUTO LISTEN REALITY_SNI DEST_HOST DEST_PORT VLESS_PORT SS_PORT HY2 HY2_PORT UUID SS_PSK SHORT_ID REALITY_PRIVATE REALITY_PUBLIC HY2_PASSWORD HY2_OBFS HY2_SNI HY2_PIN HY2_CERT_SHA256 SB_SOURCE SB_PATH FW_KIND FW_RULES"

reset_state() { local k; for k in $STATE_KEYS; do printf -v "$k" '%s' ''; done; }

# Reads KEY='value' / KEY="value" lines without executing anything, and only
# the keys listed in $2 (optionally stored under a prefix).
read_kv() {
  local file=$1 keys=" $2 " prefix=${3:-} line k v
  [ -f "$file" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    [[ $line =~ ^[A-Z0-9_]+= ]] || continue
    k=${line%%=*} v=${line#*=}
    case $keys in *" $k "*) ;; *) continue ;; esac
    if [[ $v == \'*\' || $v == \"*\" ]]; then v=${v:1:${#v}-2}; fi
    printf -v "$prefix$k" '%s' "$v"
  done <"$file"
}
load_state() { read_kv "$STATE_FILE" "$STATE_KEYS"; }
save_state() {
  local k v tmp=$STATE_FILE.new
  # shellcheck disable=SC2034 # written out below through ${!k}, like every state key
  FORMAT=1
  mkdir -p "$CONF_DIR"
  {
    printf '# OpenRoute server state (install-server.sh %s). Holds secrets: root only.\n' "$SCRIPT_VERSION"
    for k in $STATE_KEYS; do
      v=${!k}
      [[ $v != *"'"* && $v != *$'\n'* ]] || die "internal error: unsafe value for $k"
      printf "%s='%s'\n" "$k" "$v"
    done
  } | (umask 077 && cat >"$tmp")
  mv -f "$tmp" "$STATE_FILE"
}

# ---- sing-box -----------------------------------------------------------------------

SB=''
find_singbox() {
  SB=''
  if [ -n "$OPT_SINGBOX" ]; then
    [ -x "$OPT_SINGBOX" ] || die "--sing-box: $OPT_SINGBOX isn't an executable"
    SB=$OPT_SINGBOX
    return 0
  fi
  local c
  # The one this server was set up with first, so later runs use the same binary.
  for c in "$SB_PATH" "$(command -v sing-box 2>/dev/null || true)" "$ROOT/usr/bin/sing-box" "$ROOT/usr/local/bin/sing-box"; do
    if [ -n "$c" ] && [ -x "$c" ]; then SB=$c; return 0; fi
  done
  return 1
}
sb_version() { "$1" version 2>/dev/null | tr -d '\r' | sed -n 's/^sing-box version \([0-9]*\.[0-9]*\.[0-9]*\).*/\1/p'; }
version_ge() { # is $1 >= $2 (x.y.z)?
  local -a a b
  local i
  IFS=. read -r -a a <<<"$1"
  IFS=. read -r -a b <<<"$2"
  for i in 0 1 2; do
    ((10#${a[i]:-0} > 10#${b[i]:-0})) && return 0
    ((10#${a[i]:-0} < 10#${b[i]:-0})) && return 1
  done
  return 0
}
gen() {
  local out
  out=$("$SB" generate "$@" 2>&1 | tr -d '\r') || die "sing-box generate $1 failed: $(clean_log "$out")"
  printf '%s\n' "$out"
}

install_singbox() {
  local v='' src=$OPT_SOURCE
  if find_singbox; then v=$(sb_version "$SB"); fi
  if [ -z "$src" ]; then
    if [ -n "$v" ] && version_ge "$v" "$SB_MIN"; then
      ok "sing-box $v is already installed ($SB)"
      [ -n "$SB_SOURCE" ] || SB_SOURCE=existing
      SB_PATH=$SB
      return 0
    fi
    [ -z "$v" ] || note "sing-box $v is older than $SB_MIN; upgrading it"
    if have apt-get || have dnf || have yum; then src=repo; else src=release; fi
  fi
  case $src in
    existing)
      [ -n "$v" ] || die "--source existing: no sing-box found (pass --sing-box PATH)"
      version_ge "$v" "$SB_MIN" || die "sing-box $v is too old (need $SB_MIN or newer)"
      [ -n "$SB_SOURCE" ] || SB_SOURCE=existing
      SB_PATH=$SB
      ok "using sing-box $v ($SB)"
      return 0
      ;;
    repo)
      note "from SagerNet's package repository, verified against key $SAGERNET_FPR"
      if install_from_repo; then
        SB_SOURCE=repo SB_PATH=$ROOT/usr/bin/sing-box
      else
        warn "the package repository didn't work; installing the pinned $SB_PIN release instead"
        install_from_release
        SB_SOURCE=release SB_PATH=$ROOT/usr/local/bin/sing-box
      fi
      ;;
    release)
      install_from_release
      SB_SOURCE=release SB_PATH=$ROOT/usr/local/bin/sing-box
      ;;
  esac
  # Prefer the binary just installed over an older one earlier in PATH.
  [ -x "$SB_PATH" ] || SB_PATH=''
  find_singbox || die "sing-box didn't install"
  v=$(sb_version "$SB")
  version_ge "$v" "$SB_MIN" || die "sing-box ${v:-?} is too old (need $SB_MIN or newer)"
  SB_PATH=$SB
  ok "sing-box $v ($SB)"
}

install_from_repo() {
  if have apt-get; then
    # A repo already set up from SagerNet's own instructions would clash
    # with a second copy ("Conflicting values set for option Signed-By").
    if ! grep -rqs 'deb\.sagernet\.org' "$ROOT/etc/apt/sources.list" "$ROOT/etc/apt/sources.list.d/"; then
      mkdir -p "${APT_KEY%/*}" "${APT_LIST%/*}"
      sagernet_key >"$APT_KEY"
      chmod 644 "$APT_KEY"
      cat >"$APT_LIST" <<EOF
# sing-box from SagerNet's repository, added by OpenRoute's install-server.sh.
# Packages must be signed by the key in ${APT_KEY#"$ROOT"}
# (fingerprint $SAGERNET_FPR).
Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: ${APT_KEY#"$ROOT"}
EOF
    fi
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq </dev/null >/dev/null 2>&1 || warn "apt-get update reported errors; trying the install anyway"
    apt-get install -y -qq sing-box </dev/null >/dev/null 2>&1
  elif have dnf || have yum; then
    local pm=yum
    have dnf && pm=dnf
    if ! grep -rqs 'rpm\.sagernet\.org' "$ROOT/etc/yum.repos.d/"; then
      mkdir -p "${RPM_KEY%/*}" "${RPM_REPO%/*}"
      sagernet_key >"$RPM_KEY"
      chmod 644 "$RPM_KEY"
      cat >"$RPM_REPO" <<EOF
# sing-box from SagerNet's repository, added by OpenRoute's install-server.sh.
[openroute-sagernet]
name=sing-box (SagerNet)
baseurl=https://rpm.sagernet.org/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file://${RPM_KEY#"$ROOT"}
EOF
    fi
    "$pm" -y -q install sing-box </dev/null >/dev/null 2>&1
  else
    return 1
  fi
}

install_from_release() {
  local arch sum url tmp
  case $(uname -m) in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    armv7* | armv8l) arch=armv7 ;;
    i386 | i686) arch=386 ;;
    *) die "no pinned sing-box build for $(uname -m); install sing-box $SB_MIN+ yourself, then re-run with --source existing" ;;
  esac
  sum=$(sb_pin_sha256 "$arch")
  url=https://github.com/SagerNet/sing-box/releases/download/v$SB_PIN/sing-box-$SB_PIN-linux-$arch.tar.gz
  tmp=$(mktemp -d)
  note "downloading $url"
  if ! curl -fsSL --retry 3 --max-time 300 -o "$tmp/sing-box.tar.gz" "$url"; then
    rm -rf "$tmp"
    die "couldn't download sing-box from GitHub"
  fi
  if [ "$(sha256_hex <"$tmp/sing-box.tar.gz")" != "$sum" ]; then
    rm -rf "$tmp"
    die "the downloaded sing-box doesn't match its pinned SHA-256 ($sum); not installing it"
  fi
  tar -xzf "$tmp/sing-box.tar.gz" -C "$tmp"
  mkdir -p "$ROOT/usr/local/bin"
  install -m 0755 "$tmp/sing-box-$SB_PIN-linux-$arch/sing-box" "$ROOT/usr/local/bin/sing-box"
  rm -rf "$tmp"
  ok "installed sing-box $SB_PIN (SHA-256 verified) to /usr/local/bin/sing-box"
}

# ---- credentials ---------------------------------------------------------------------

# Fills in whatever is missing, so re-running keeps every existing secret
# (and with it every link already handed out).
new_credentials() {
  [ -n "$UUID" ] || UUID=$(gen uuid)
  [ -n "$SS_PSK" ] || SS_PSK=$(gen rand 16 --base64)
  [ -n "$SHORT_ID" ] || SHORT_ID=$(gen rand 8 --hex)
  if [ -z "$REALITY_PRIVATE" ] || [ -z "$REALITY_PUBLIC" ]; then
    local kp
    kp=$(gen reality-keypair)
    REALITY_PRIVATE=$(sed -n 's/^PrivateKey: *//p' <<<"$kp")
    REALITY_PUBLIC=$(sed -n 's/^PublicKey: *//p' <<<"$kp")
  fi
  if [ "$HY2" = 1 ]; then
    [ -n "$HY2_PASSWORD" ] || HY2_PASSWORD=$(gen rand 16 --hex)
    [ -n "$HY2_OBFS" ] || HY2_OBFS=$(gen rand 16 --hex)
    [ -n "$HY2_SNI" ] || HY2_SNI=$REALITY_SNI
    if [ -z "$HY2_PIN" ] || [ ! -s "$HY2_CERT" ] || [ ! -s "$HY2_KEY" ]; then new_hy2_certificate; fi
  else
    HY2_PORT='' HY2_PASSWORD='' HY2_OBFS='' HY2_SNI='' HY2_PIN='' HY2_CERT_SHA256=''
    rm -f "$HY2_CERT" "$HY2_KEY"
  fi
  local re_uuid='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  local re_psk='^[A-Za-z0-9+/]{22}==$' re_key='^[A-Za-z0-9_-]{43}$'
  [[ $UUID =~ $re_uuid && $SS_PSK =~ $re_psk && $SHORT_ID =~ ^[0-9a-f]{16}$ &&
    $REALITY_PRIVATE =~ $re_key && $REALITY_PUBLIC =~ $re_key ]] ||
    die "sing-box produced credentials in an unexpected format; please report this ($REPO_URL/issues)"
}

clear_credentials() {
  UUID='' SS_PSK='' SHORT_ID='' REALITY_PRIVATE='' REALITY_PUBLIC=''
  HY2_PASSWORD='' HY2_OBFS='' HY2_SNI='' HY2_PIN='' HY2_CERT_SHA256=''
  rm -f "$HY2_CERT" "$HY2_KEY"
}

new_hy2_certificate() {
  have openssl || die "Hysteria2 needs openssl to compute its certificate pin"
  local kp
  kp=$(gen tls-keypair "$HY2_SNI" --months 120)
  mkdir -p "$CONF_DIR"
  (
    umask 077
    sed -n '/-BEGIN PRIVATE KEY-/,/-END PRIVATE KEY-/p' <<<"$kp" >"$HY2_KEY"
    sed -n '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' <<<"$kp" >"$HY2_CERT"
  )
  [ -s "$HY2_KEY" ] && [ -s "$HY2_CERT" ] || die "sing-box didn't produce a Hysteria2 certificate"
  # Clients check one of these instead of a CA: the SHA-256 of the public
  # key (sing-box's certificate_public_key_sha256, which OpenRoute uses) and
  # of the whole certificate (Hysteria's standard pinSHA256, for other apps).
  HY2_PIN=$(openssl x509 -pubkey -noout <"$HY2_CERT" | openssl pkey -pubin -outform der | sha256_hex)
  HY2_CERT_SHA256=$(openssl x509 -outform der <"$HY2_CERT" | sha256_hex)
  [[ $HY2_PIN =~ ^[0-9a-f]{64}$ && $HY2_CERT_SHA256 =~ ^[0-9a-f]{64}$ ]] || die "couldn't compute the Hysteria2 certificate pin"
}

# ---- ports -------------------------------------------------------------------------

# ss columns: Netid State Recv-Q Send-Q Local-Address:Port Peer-Address:Port [Process]
port_in() { awk -v p="$1" 'NR > 1 { n = split($5, a, ":"); if (a[n] == p) f = 1 } END { exit !f }'; }
port_busy() { have ss && ss -lntu 2>/dev/null | port_in "$1"; }
port_listening() { ss -ln"${1:0:1}" 2>/dev/null | port_in "$2"; } # tcp|udp PORT
port_owner() { ss -lntup 2>/dev/null | awk -v p="$1" 'NR > 1 { n = split($5, a, ":"); if (a[n] == p && $7 != "") { print $7; exit } }' || true; }

random_port() { # a free port in 20000-39999 that isn't one of "$@"
  local p i t clash
  for ((i = 0; i < 200; i++)); do
    p=$((20000 + (RANDOM * 32768 + RANDOM) % 20000))
    clash=0
    for t in "$@"; do [ "$p" != "$t" ] || clash=1; done
    [ "$clash" = 0 ] || continue
    port_busy "$p" && continue
    printf '%s' "$p"
    return 0
  done
  die "couldn't find a free port between 20000 and 39999"
}

# Explicit options win, then what's installed, then fresh picks.
assign_ports() {
  local held=' ' p owner
  if [ "$SYSTEM_MODE" = 1 ] && svc_active; then held=" $VLESS_PORT $SS_PORT $HY2_PORT "; fi
  [ -z "$OPT_VLESS_PORT" ] || VLESS_PORT=$OPT_VLESS_PORT
  [ -n "$VLESS_PORT" ] || VLESS_PORT=443
  [ -z "$OPT_SS_PORT" ] || SS_PORT=$OPT_SS_PORT
  [ -n "$SS_PORT" ] || SS_PORT=$(random_port "$VLESS_PORT" "$HY2_PORT")
  if [ "$HY2" = 1 ]; then
    [ -z "$OPT_HY2_PORT" ] || HY2_PORT=$OPT_HY2_PORT
    [ -n "$HY2_PORT" ] || HY2_PORT=$(random_port "$VLESS_PORT" "$SS_PORT")
  else
    HY2_PORT=''
  fi
  [ "$VLESS_PORT" != "$SS_PORT" ] || die "VLESS and Shadowsocks can't share port $SS_PORT (both use TCP)"
  [ "$HY2" != 1 ] || [ "$SS_PORT" != "$HY2_PORT" ] || die "Shadowsocks and Hysteria2 can't share port $SS_PORT (both use UDP)"
  [ "$SYSTEM_MODE" = 1 ] || return 0
  for p in $VLESS_PORT $SS_PORT $HY2_PORT; do
    case $held in *" $p "*) continue ;; esac
    if port_busy "$p"; then
      owner=$(port_owner "$p")
      die "port $p is already in use${owner:+ by $owner}. Free it, or pick another with --vless-port / --ss-port / --hy2-port."
    fi
  done
}

effective_listen() {
  if [ -n "$LISTEN" ]; then
    printf '%s' "$LISTEN"
  elif [ -s "$PROC/net/if_inet6" ]; then
    printf '::' # dual-stack: IPv4 and IPv6
  else
    printf '0.0.0.0' # binding :: fails where IPv6 is switched off
  fi
}

# ---- the config ------------------------------------------------------------------------

render_config() {
  local listen dest_host=${DEST_HOST:-$REALITY_SNI} dest_port=${DEST_PORT:-443} hy2=''
  listen=$(effective_listen)
  if [ "$HY2" = 1 ]; then
    hy2=$(
      cat <<EOF
,
    {
      "type": "hysteria2",
      "tag": "hysteria2-in",
      "listen": "$listen",
      "listen_port": $HY2_PORT,
      "users": [{ "name": "openroute", "password": "$HY2_PASSWORD" }],
      "obfs": { "type": "salamander", "password": "$HY2_OBFS" },
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": $(json_str "$HY2_CERT"),
        "key_path": $(json_str "$HY2_KEY")
      }
    }
EOF
    )
  fi
  # route: "resolve" first, so a client asking for a *name* that points at
  # a private address (localhost, metadata.google.internal, …) is caught by
  # the address rules too: they only ever see IPs. Port 25 is refused so the
  # server can't be used to send spam, which gets VPS accounts closed.
  cat <<EOF
{
  "log": { "level": "warn", "timestamp": true },
  "dns": {
    "servers": [{ "type": "local", "tag": "system" }],
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality-in",
      "listen": "$listen",
      "listen_port": $VLESS_PORT,
      "users": [{ "name": "openroute", "uuid": "$UUID", "flow": "xtls-rprx-vision" }],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SNI",
        "reality": {
          "enabled": true,
          "handshake": { "server": "$dest_host", "server_port": $dest_port },
          "private_key": "$REALITY_PRIVATE",
          "short_id": ["$SHORT_ID"]
        }
      }
    },
    {
      "type": "shadowsocks",
      "tag": "ss2022-in",
      "listen": "$listen",
      "listen_port": $SS_PORT,
      "method": "$SS_METHOD",
      "password": "$SS_PSK"
    }$hy2
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": {
    "default_domain_resolver": "system",
    "rules": [
      { "action": "resolve" },
      { "ip_is_private": true, "action": "reject" },
      { "ip_cidr": [$BLOCKED_CIDRS], "action": "reject" },
      { "port": [25], "action": "reject" }
    ],
    "final": "direct"
  }
}
EOF
}

render_links() {
  local h n=${NAME:-OpenRoute}
  h=$(link_host "$HOST")
  printf 'vless://%s@%s:%s?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#%s\n' \
    "$UUID" "$h" "$VLESS_PORT" "$REALITY_SNI" "$REALITY_PUBLIC" "$SHORT_ID" "$(urlencode "$n Reality")"
  if [ "$HY2" = 1 ]; then
    printf 'hysteria2://%s@%s:%s/?sni=%s&obfs=salamander&obfs-password=%s&pinSHA256=%s&pinPublicKeySHA256=%s#%s\n' \
      "$HY2_PASSWORD" "$h" "$HY2_PORT" "$HY2_SNI" "$HY2_OBFS" "$HY2_CERT_SHA256" "$HY2_PIN" "$(urlencode "$n Hysteria2")"
  fi
  # SIP002 for AEAD-2022 ciphers: plain method:password, percent-encoded, not base64.
  printf 'ss://%s:%s@%s:%s#%s\n' "$SS_METHOD" "$(urlencode "$SS_PSK")" "$h" "$SS_PORT" "$(urlencode "$n SS-2022")"
}

# Writes config.json (checked by sing-box itself first), links.txt and the state.
write_files() {
  local tmp=$CONF_DIR/config.new.json out
  mkdir -p "$CONF_DIR"
  (umask 077 && render_config >"$tmp")
  if ! out=$("$SB" check -c "$tmp" 2>&1); then
    rm -f "$tmp"
    die "sing-box $(sb_version "$SB") rejected the generated config; please report this ($REPO_URL/issues): $(clean_log "$out")"
  fi
  mv -f "$tmp" "$CONFIG"
  (umask 077 && render_links >"$LINKS_FILE.new")
  mv -f "$LINKS_FILE.new" "$LINKS_FILE"
  save_state
}

# ---- system integration -------------------------------------------------------------------

ensure_user() {
  getent passwd "$SVC_USER" >/dev/null 2>&1 && return 0
  local nologin=/usr/sbin/nologin
  [ -x "$nologin" ] || nologin=/sbin/nologin
  useradd --system --no-create-home --home-dir "/var/lib/$SVC" --shell "$nologin" --user-group "$SVC_USER" >/dev/null 2>&1 ||
    useradd -r -M -d "/var/lib/$SVC" -s "$nologin" -U "$SVC_USER" ||
    die "couldn't create the $SVC_USER system user"
  ok "created system user $SVC_USER"
}

secure_files() {
  chown root:"$SVC_USER" "$CONF_DIR" "$CONFIG"
  chmod 750 "$CONF_DIR"
  chmod 640 "$CONFIG"
  if [ "$HY2" = 1 ]; then
    chown root:"$SVC_USER" "$HY2_CERT" "$HY2_KEY"
    chmod 640 "$HY2_CERT" "$HY2_KEY"
  fi
  chmod 600 "$STATE_FILE" "$LINKS_FILE"
  mkdir -p "$STATE_DIR"
  chown "$SVC_USER:$SVC_USER" "$STATE_DIR"
  chmod 700 "$STATE_DIR"
}

write_unit() {
  local config=${CONFIG#"$ROOT"} sb=${SB#"$ROOT"}
  mkdir -p "${UNIT_FILE%/*}"
  cat >"$UNIT_FILE" <<EOF
# Written by OpenRoute's install-server.sh; "install-server.sh uninstall" removes it.
[Unit]
Description=OpenRoute server (sing-box)
Documentation=$REPO_URL/tree/main/server
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
ExecStartPre=$sb check -c $config
ExecStart=$sb run -D /var/lib/$SVC -c $config
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
StateDirectory=$SVC
StateDirectoryMode=0700
UMask=0077
# A proxy needs to bind ports below 1024 and nothing else.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
EOF
}

svc_active() { systemctl is-active --quiet "$SVC" 2>/dev/null; }

all_listening() {
  svc_active || return 1
  have ss || return 0 # can't look; systemd's word will have to do
  port_listening tcp "$VLESS_PORT" && port_listening tcp "$SS_PORT" && port_listening udp "$SS_PORT" &&
    { [ "$HY2" != 1 ] || port_listening udp "$HY2_PORT"; }
}

start_service() {
  local i
  systemctl daemon-reload
  systemctl enable "$SVC" >/dev/null 2>&1 || warn "couldn't enable $SVC at boot"
  if systemctl restart "$SVC"; then
    for ((i = 0; i < 40; i++)); do
      if all_listening; then
        ok "$SVC is running and listening on $(describe_ports)"
        return 0
      fi
      sleep 0.25
    done
  fi
  journalctl -u "$SVC" -n 25 --no-pager >&2 2>/dev/null || true # its log to stderr, its own errors away
  die "$SVC didn't come up (its log is above). For a checklist: sudo bash install-server.sh doctor"
}

describe_ports() {
  printf 'TCP %s, TCP+UDP %s' "$VLESS_PORT" "$SS_PORT"
  [ "$HY2" != 1 ] || printf ', UDP %s' "$HY2_PORT"
}

# ---- firewall ------------------------------------------------------------------------------

wanted_rules() {
  printf '%s/tcp %s/tcp %s/udp' "$VLESS_PORT" "$SS_PORT" "$SS_PORT"
  [ "$HY2" != 1 ] || printf ' %s/udp' "$HY2_PORT"
}

# Matches a command's output against an ERE without piping into grep -q:
# under pipefail, `cmd | grep -q` "fails" whenever grep exits before cmd is
# done writing (SIGPIPE), which can make an active firewall look absent.
output_has() {
  local re=$1 out
  shift
  out=$("$@" 2>/dev/null) || true
  grep -Eq -- "$re" <<<"$out"
}

fw_detect() {
  if have ufw && output_has '^Status: active' ufw status; then
    echo ufw
  elif have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    echo firewalld
  elif have iptables && output_has '^-P INPUT (DROP|REJECT)|-j (DROP|REJECT)' iptables -S INPUT; then
    echo iptables # e.g. Oracle Cloud's images, which REJECT everything but SSH
  elif have nft && output_has 'hook input .*policy drop' nft list ruleset; then
    echo nftables
  else
    echo none
  fi
}

ufw_rule_number() { # first numbered rule carrying our comment for port/proto $1
  ufw status numbered 2>/dev/null | awk -v r="$1" -v c="# $SVC" '
    /^\[ *[0-9]+\]/ && index($0, c) {
      num = $0; sub(/^\[ */, "", num); sub(/\].*/, "", num)
      rest = $0; sub(/^\[ *[0-9]+\] */, "", rest); split(rest, f, " ")
      if (f[1] == r) { print num; exit }
    }' || true
}

ipt() { # -I|-D proto port, for IPv4 and IPv6
  local op=$1 proto=$2 port=$3 t
  for t in iptables ip6tables; do
    have "$t" || continue
    if [ "$op" = -I ]; then
      "$t" -C INPUT -p "$proto" --dport "$port" -m comment --comment "$SVC" -j ACCEPT 2>/dev/null ||
        "$t" -I INPUT -p "$proto" --dport "$port" -m comment --comment "$SVC" -j ACCEPT 2>/dev/null ||
        [ "$t" = ip6tables ] || warn "iptables: couldn't open $port/$proto"
    else
      while "$t" -D INPUT -p "$proto" --dport "$port" -m comment --comment "$SVC" -j ACCEPT 2>/dev/null; do :; done
    fi
  done
}

ipt_persist() {
  if have netfilter-persistent && netfilter-persistent save >/dev/null 2>&1; then return 0; fi
  if [ -d "$ROOT/etc/iptables" ]; then
    iptables-save >"$ROOT/etc/iptables/rules.v4"
    ! have ip6tables-save || ip6tables-save >"$ROOT/etc/iptables/rules.v6"
    return 0
  fi
  if [ -f "$ROOT/etc/sysconfig/iptables" ]; then
    iptables-save >"$ROOT/etc/sysconfig/iptables"
    [ ! -f "$ROOT/etc/sysconfig/ip6tables" ] || ip6tables-save >"$ROOT/etc/sysconfig/ip6tables"
    return 0
  fi
  warn "iptables rules added for now, but nothing here saves them across reboots (install iptables-persistent)"
}

fw_open() { # kind port/proto
  case $1 in
    ufw) ufw allow "$2" comment "$SVC" >/dev/null ;;
    firewalld) firewall-cmd --quiet --permanent --add-port="$2" ;;
    iptables) ipt -I "${2#*/}" "${2%/*}" ;;
  esac
}
fw_close() { # kind port/proto
  local n
  case $1 in
    ufw)
      # By number: matching a rule by its spec can miss commented rules.
      while n=$(ufw_rule_number "$2") && [ -n "$n" ]; do
        ufw --force delete "$n" >/dev/null 2>&1 || break
      done
      ;;
    firewalld) firewall-cmd --quiet --permanent --remove-port="$2" >/dev/null 2>&1 || true ;;
    iptables) ipt -D "${2#*/}" "${2%/*}" ;;
  esac
}
fw_commit() {
  case $1 in
    firewalld) firewall-cmd --quiet --reload || warn "firewalld didn't reload" ;;
    iptables) ipt_persist ;;
  esac
}
fw_allows() { # kind port/proto
  case $1 in
    ufw) output_has "^$2[[:space:]]+ALLOW" ufw status ;;
    firewalld) output_has "(^| )$2( |$)" firewall-cmd --list-ports ;;
    iptables) iptables -C INPUT -p "${2#*/}" --dport "${2%/*}" -m comment --comment "$SVC" -j ACCEPT 2>/dev/null ;;
    none) return 0 ;;
    *) return 1 ;;
  esac
}

# Makes the firewall allow exactly our current ports: closes the ones we
# opened before and no longer use, (re)opens the rest.
firewall_sync() {
  local kind new r
  kind=$(fw_detect)
  new=$(wanted_rules)
  if [ -n "$FW_KIND" ] && [ "$FW_KIND" != "$kind" ]; then
    for r in $FW_RULES; do fw_close "$FW_KIND" "$r"; done
    fw_commit "$FW_KIND"
    FW_RULES=''
  fi
  for r in $FW_RULES; do
    case " $new " in *" $r "*) ;; *) fw_close "$kind" "$r" ;; esac
  done
  for r in $new; do fw_open "$kind" "$r"; done
  fw_commit "$kind"
  case $kind in
    none)
      FW_KIND='' FW_RULES=''
      note "no active host firewall found; nothing to open"
      ;;
    nftables)
      FW_KIND='' FW_RULES=''
      warn "nftables drops incoming traffic here and this script won't edit your ruleset; allow $(describe_ports) yourself"
      ;;
    *)
      FW_KIND=$kind FW_RULES=$new
      ok "$kind allows $(describe_ports)"
      ;;
  esac
}

# ---- tuning --------------------------------------------------------------------------------

enable_bbr() {
  local cc=$PROC/sys/net/ipv4/tcp_available_congestion_control
  grep -qw bbr "$cc" 2>/dev/null || modprobe tcp_bbr >/dev/null 2>&1 || true
  if ! grep -qw bbr "$cc" 2>/dev/null; then
    note "this kernel has no BBR; congestion control left as it is"
    return 0
  fi
  mkdir -p "${SYSCTL_FILE%/*}"
  cat >"$SYSCTL_FILE" <<'EOF'
# Written by OpenRoute's install-server.sh; its uninstall removes this file.
# BBR congestion control: far better throughput on long, lossy paths.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
# Bigger socket buffers for QUIC (Hysteria2) and long fat pipes.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
EOF
  if sysctl -q -p "$SYSCTL_FILE" >/dev/null 2>&1; then
    ok "BBR congestion control enabled"
  else
    warn "BBR settings written, but they couldn't be applied now (containers often forbid it); they apply at boot where allowed"
  fi
}

ensure_time_sync() {
  have timedatectl || return 0
  timedatectl set-ntp true >/dev/null 2>&1 || true
  if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)" = yes ]; then
    ok "clock is NTP-synchronized"
  else
    warn "the clock isn't NTP-synchronized (yet). Shadowsocks-2022 refuses clients more than 30 s off, so keep an eye on: timedatectl"
  fi
}

# ---- choosing the cover site and address ------------------------------------------------------

# Prints the handshake time in ms when SNI $1 (reached at $2:$3) offers
# TLS 1.3, HTTP/2 and X25519 with a certificate valid for that name: what a
# Reality cover site needs.
sni_handshake_ms() {
  local sni=$1 host=${2:-$1} port=${3:-443} out t0 t1
  t0=$(date +%s%N)
  out=$(timeout 10 openssl s_client -connect "$(link_host "$host"):$port" -servername "$sni" -tls1_3 -alpn h2 \
    -groups X25519 -verify_return_error -verify_hostname "$sni" </dev/null 2>&1) || return 1
  t1=$(date +%s%N)
  grep -q '^ALPN protocol: h2' <<<"$out" && grep -q 'TLSv1\.3' <<<"$out" && grep -q 'Verify return code: 0 (ok)' <<<"$out" || return 1
  if [[ $t0 =~ ^[0-9]+$ && $t1 =~ ^[0-9]+$ ]]; then echo $(((t1 - t0) / 1000000)); else echo 0; fi
}

auto_sni() {
  local d h ms best
  d=$(mktemp -d)
  for h in $SNI_CANDIDATES; do
    (if ms=$(sni_handshake_ms "$h"); then printf '%s %s\n' "$ms" "$h" >"$d/$h"; fi) &
  done
  wait
  best=$(cat "$d"/* 2>/dev/null | sort -n | awk 'NR == 1 { print $2 }')
  rm -rf "$d"
  [ -n "$best" ] || return 1
  printf '%s' "$best"
}

pick_sni() {
  local ms
  if [ "$OPT_SNI" = auto ] || { [ -z "$OPT_SNI" ] && [ -z "$REALITY_SNI" ]; }; then
    note "testing which big site answers this server fastest over TLS 1.3 + HTTP/2"
    REALITY_SNI=$(auto_sni) ||
      die "none of these passed a TLS 1.3 + HTTP/2 check from this server: $SNI_CANDIDATES. Check its outbound HTTPS, or pass --sni with a site that works."
    ok "Reality will look like a visit to $REALITY_SNI"
    return 0
  fi
  [ -z "$OPT_SNI" ] || REALITY_SNI=$OPT_SNI
  if [ "$OPT_SKIP_SNI" = 1 ]; then
    note "using $REALITY_SNI without testing it (--skip-sni-check)"
  elif ms=$(sni_handshake_ms "$REALITY_SNI" "${DEST_HOST:-$REALITY_SNI}" "${DEST_PORT:-443}"); then
    ok "Reality will look like a visit to $REALITY_SNI (TLS 1.3 + HTTP/2, ${ms} ms from here)"
  elif [ -n "$OPT_SNI" ]; then
    die "$REALITY_SNI doesn't offer TLS 1.3 + HTTP/2 with a valid certificate from this server, which Reality needs. Pick another --sni, or use --sni auto."
  else
    # Changing it would change every link; a failed check can be a blip.
    warn "$REALITY_SNI didn't pass the TLS 1.3 + HTTP/2 check just now; keeping it so your links stay valid. If Reality stops working, re-run with --sni auto."
  fi
}

detect_public_ip() {
  local url ip
  for url in https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip; do
    ip=$(curl -4 -fsS --max-time 6 "$url" 2>/dev/null | tr -d ' \r\n' || true)
    if is_ipv4 "$ip"; then printf '%s' "$ip"; return 0; fi
  done
  for url in https://api6.ipify.org https://ipv6.icanhazip.com; do
    ip=$(curl -6 -fsS --max-time 6 "$url" 2>/dev/null | tr -d ' \r\n' || true)
    if is_ipv6 "$ip"; then printf '%s' "$ip"; return 0; fi
  done
  return 1
}

pick_host() {
  local ip
  if [ -n "$OPT_HOST" ]; then
    HOST=$OPT_HOST HOST_AUTO=0
    ok "links will use $HOST"
    return 0
  fi
  if [ -n "$HOST" ] && [ "$HOST_AUTO" != 1 ]; then return 0; fi
  if ! ip=$(detect_public_ip); then
    [ -z "$HOST" ] || { warn "couldn't re-detect the public IP; keeping $HOST"; return 0; }
    die "couldn't detect this server's public IP; pass --host <ip or domain>"
  fi
  if [ -n "$HOST" ] && [ "$HOST" != "$ip" ]; then
    warn "the public IP changed from $HOST to $ip; the links below use the new one, so paste them again"
  fi
  HOST=$ip HOST_AUTO=1
  ok "public address: $HOST"
}

# ---- upgrading a v0.3 install ------------------------------------------------------------------

# v0.3 ran the sing-box package's own service with its config in
# /etc/sing-box. Keep its credentials and ports so handed-out links keep
# working, then retire that setup.
migrate_legacy() {
  [ -f "$LEGACY_ENV" ] && [ ! -f "$STATE_FILE" ] || return 0
  if ! grep -qs '"tag": "vless-in"' "$LEGACY_CONFIG" || ! grep -qs '"tag": "ss-in"' "$LEGACY_CONFIG"; then
    warn "found $LEGACY_ENV from OpenRoute v0.3, but $LEGACY_CONFIG isn't its config any more; leaving both alone"
    return 0
  fi
  step "Upgrading the OpenRoute v0.3 server on this machine"
  read_kv "$LEGACY_ENV" "UUID SS_PSK SS_PORT VLESS_PORT REALITY_SNI REALITY_PUBLIC SHORT_ID SERVER_IP" OLD_
  UUID=${OLD_UUID:-} SS_PSK=${OLD_SS_PSK:-} SS_PORT=${OLD_SS_PORT:-} VLESS_PORT=${OLD_VLESS_PORT:-}
  REALITY_SNI=${OLD_REALITY_SNI:-} REALITY_PUBLIC=${OLD_REALITY_PUBLIC:-} SHORT_ID=${OLD_SHORT_ID:-}
  HOST=${OLD_SERVER_IP:-} HOST_AUTO=1
  REALITY_PRIVATE=$(sed -n 's/.*"private_key": *"\([^"]*\)".*/\1/p' "$LEGACY_CONFIG")
  local re_key='^[A-Za-z0-9_-]{43}$'
  if [[ -n $UUID && -n $SS_PSK && $REALITY_PRIVATE =~ $re_key && $REALITY_PUBLIC =~ $re_key ]] &&
    is_port "$SS_PORT" && is_port "$VLESS_PORT" && is_hostname "$REALITY_SNI"; then
    ok "kept its credentials and ports, so the links you already use keep working"
  else
    warn "couldn't read all of its credentials; issuing new ones (paste the new links)"
    clear_credentials
    SS_PORT='' VLESS_PORT='' REALITY_SNI=''
  fi
  if systemctl disable --now sing-box >/dev/null 2>&1; then ok "stopped the old sing-box service"; fi
  mv -f "$LEGACY_ENV" "$LEGACY_ENV.migrated"
  mv -f "$LEGACY_CONFIG" "$LEGACY_CONFIG.openroute-v0.3.bak"
  note "old files kept as ${LEGACY_ENV#"$ROOT"}.migrated and ${LEGACY_CONFIG#"$ROOT"}.openroute-v0.3.bak"
}

# The sing-box package ships /etc/sing-box/config.json as a *sample*: an
# open Shadowsocks proxy on port 8080 whose password is published on GitHub.
warn_vendor_sample() {
  if systemctl is-active --quiet sing-box 2>/dev/null && grep -qs 'Gn1JUS14bLUHgv1cWDDp4A==' "$ROOT/etc/sing-box/config.json"; then
    warn "the sing-box package's own service is running its SAMPLE config: an open proxy on port 8080 with a published password. Stop it: systemctl disable --now sing-box"
    return 1
  fi
}

# ---- prerequisites -----------------------------------------------------------------------------

install_prereqs() {
  local -a want=()
  local c
  for c in curl openssl ss sha256sum timeout; do
    have "$c" && continue
    case $c in
      ss) want+=(iproute) ;;
      sha256sum | timeout) want+=(coreutils) ;;
      *) want+=("$c") ;;
    esac
  done
  if [ ${#want[@]} -gt 0 ]; then
    note "installing ${want[*]}"
    if have apt-get; then
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq </dev/null >/dev/null 2>&1 || warn "apt-get update reported errors; carrying on"
      apt-get install -y -qq --no-install-recommends ca-certificates "${want[@]/#iproute/iproute2}" </dev/null >/dev/null 2>&1 || true
    elif have dnf; then
      dnf -y -q install ca-certificates "${want[@]}" </dev/null >/dev/null 2>&1 || true
    elif have yum; then
      yum -y -q install ca-certificates "${want[@]}" </dev/null >/dev/null 2>&1 || true
    fi
  fi
  for c in curl openssl ss sha256sum timeout; do have "$c" || die "$c is required; install it and re-run"; done
  if [ "$OPT_QR" = 1 ] && ! have qrencode; then
    if have apt-get; then
      apt-get install -y -qq --no-install-recommends qrencode </dev/null >/dev/null 2>&1 || true
    elif have dnf; then
      dnf -y -q install qrencode </dev/null >/dev/null 2>&1 || true
    elif have yum; then
      yum -y -q install qrencode </dev/null >/dev/null 2>&1 || true
    fi
  fi
  ok "curl, openssl and ss are present$(have qrencode && printf ', and qrencode for QR codes')"
}

describe_os() {
  local name=''
  [ ! -r "$ROOT/etc/os-release" ] || name=$(sed -n 's/^PRETTY_NAME=//p' "$ROOT/etc/os-release" | tr -d '"')
  ok "${name:-Linux} on $(uname -m)"
}

# ---- commands ----------------------------------------------------------------------------------

apply_options() {
  [ -z "$OPT_HY2" ] || HY2=$OPT_HY2
  [ -n "$HY2" ] || HY2=0
  [ -z "$OPT_NAME" ] || NAME=$OPT_NAME
  [ -z "$OPT_LISTEN" ] || LISTEN=$OPT_LISTEN
  if [ -n "$OPT_DEST" ]; then DEST_HOST=$OPT_DEST_HOST DEST_PORT=$OPT_DEST_PORT; fi
}

# Shared by install and rotate: write everything, start, verify, report.
apply_and_start() {
  step "Writing the configuration"
  ensure_user
  new_credentials
  write_files
  secure_files
  write_unit
  ok "config at ${CONFIG#"$ROOT"} (checked by sing-box), service $SVC"
  if [ "$OPT_FIREWALL" = 1 ]; then
    step "Firewall"
    firewall_sync
  fi
  if [ "$OPT_BBR" = 1 ]; then
    step "Network tuning"
    enable_bbr
  fi
  ensure_time_sync
  step "Starting $SVC"
  start_service
  save_state
  warn_vendor_sample || true
}

cmd_install() {
  need_root
  need_systemd
  lock
  step "This system"
  describe_os
  load_state || true
  migrate_legacy
  apply_options
  step "Prerequisites"
  install_prereqs
  step "sing-box"
  install_singbox
  step "Reality cover site"
  pick_sni
  step "Address and ports"
  pick_host
  assign_ports
  ok "VLESS-Reality on TCP $VLESS_PORT, Shadowsocks-2022 on TCP+UDP $SS_PORT$([ "$HY2" != 1 ] || printf ', Hysteria2 on UDP %s' "$HY2_PORT")"
  apply_and_start
  show_links
}

cmd_rotate() {
  need_root
  need_systemd
  lock
  load_state || die "nothing to rotate: the OpenRoute server isn't installed here (run: sudo bash install-server.sh)"
  find_singbox || die "sing-box is missing; run install again first"
  apply_options
  step "New credentials"
  clear_credentials
  if [ "$OPT_NEW_PORTS" = 1 ]; then SS_PORT='' HY2_PORT=''; fi
  if [ -n "$OPT_SNI" ]; then pick_sni; fi
  [ -z "$OPT_HOST" ] || pick_host
  assign_ports
  ok "fresh UUID, Shadowsocks key, Reality key pair$([ "$HY2" != 1 ] || printf ' and Hysteria2 certificate')"
  apply_and_start
  say ""
  say "${BOLD}The old links no longer work.${OFF} Replace them with these:"
  show_links
}

cmd_show() {
  need_root
  load_state || die "the OpenRoute server isn't installed here; to install it: sudo bash install-server.sh"
  show_links
}

show_links() {
  local links line
  links=$(render_links)
  say ""
  say "${BOLD}Your share links${OFF}"
  say "In the OpenRoute popup: Transports → Connect via companion, and paste them all"
  say "(one per line): the companion fails over between them automatically."
  say ""
  say "$links"
  if [ "$OPT_QR" = 1 ] && have qrencode; then
    while IFS= read -r line; do
      say ""
      say "  ${line%%://*}:"
      qrencode -t ANSIUTF8 -m 2 "$line" || true
    done <<<"$links"
  fi
  say ""
  note "print them again any time: sudo bash install-server.sh show"
  [ "$HY2" != 1 ] || note "the Hysteria2 link pins this server's self-signed certificate; read server/README.md before using it in other apps"
  note "your provider's own firewall (AWS security groups, Oracle / GCP / Azure network rules, …) must allow $(describe_ports)"
}

cmd_doctor() {
  need_root
  local problems=0 v out kind r ip ms spec proto port what
  problem() { printf '  %s✗%s %s\n' "$RED" "$OFF" "$*"; problems=$((problems + 1)); }
  step "OpenRoute server doctor"
  load_state || { problem "not installed (${STATE_FILE#"$ROOT"} is missing): sudo bash install-server.sh"; exit 1; }

  if find_singbox; then
    v=$(sb_version "$SB")
    if version_ge "$v" "$SB_MIN"; then ok "sing-box $v ($SB)"; else problem "sing-box ${v:-?} is too old (need $SB_MIN+): run install again"; fi
    if out=$("$SB" check -c "$CONFIG" 2>&1); then ok "sing-box accepts the config"; else problem "sing-box rejects the config ($(clean_log "$out")): run install again to regenerate it"; fi
  else
    problem "sing-box isn't installed: run install again"
  fi

  if svc_active; then ok "$SVC is running"; else problem "$SVC isn't running; see: journalctl -u $SVC -n 30"; fi
  if have ss; then
    for spec in "tcp $VLESS_PORT VLESS-Reality" "tcp $SS_PORT Shadowsocks-2022" "udp $SS_PORT Shadowsocks-2022" ${HY2_PORT:+"udp $HY2_PORT Hysteria2"}; do
      read -r proto port what <<<"$spec"
      if port_listening "$proto" "$port"; then ok "$what listens on $proto $port"; else problem "$what isn't listening on $proto $port"; fi
    done
  fi

  kind=$(fw_detect)
  case $kind in
    none) ok "no host firewall in the way" ;;
    nftables) problem "nftables filters incoming traffic; make sure it allows $(describe_ports)" ;;
    *)
      for r in $(wanted_rules); do
        if fw_allows "$kind" "$r"; then ok "$kind allows $r"; else problem "$kind doesn't allow $r: run install again"; fi
      done
      ;;
  esac

  if have openssl; then
    if ms=$(sni_handshake_ms "$REALITY_SNI" "${DEST_HOST:-$REALITY_SNI}" "${DEST_PORT:-443}"); then
      ok "cover site $REALITY_SNI: TLS 1.3 + HTTP/2, ${ms} ms away"
    else
      problem "cover site $REALITY_SNI fails the TLS 1.3 + HTTP/2 check from here; Reality needs it: rotate --sni auto (links change)"
    fi
  fi
  if [ "$HOST_AUTO" = 1 ] && ip=$(detect_public_ip); then
    if [ "$ip" = "$HOST" ]; then ok "the links' address $HOST is still this server's"; else problem "the public IP is now $ip but the links say $HOST: run install again"; fi
  fi
  if have timedatectl; then
    if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)" = yes ]; then ok "clock is NTP-synchronized"; else problem "clock isn't NTP-synchronized; Shadowsocks-2022 refuses clients more than 30 s off: timedatectl set-ntp true"; fi
  fi
  warn_vendor_sample || problems=$((problems + 1))
  note "can't be checked from inside: your provider's firewall must allow $(describe_ports)"
  say ""
  if [ "$problems" = 0 ]; then
    ok "no problems found"
  else
    say "$problems problem(s) found."
    exit 1
  fi
}

cmd_uninstall() {
  need_root
  lock
  load_state || warn "no ${STATE_FILE#"$ROOT"}; removing whatever is left"
  if [ "$OPT_YES" != 1 ]; then
    { : </dev/tty; } 2>/dev/null || die "nothing to ask on; add --yes to confirm"
    local ans=''
    printf 'Remove the OpenRoute server%s? Its links stop working. [y/N] ' "$([ "$OPT_PURGE" != 1 ] || printf ' and sing-box')" >/dev/tty
    read -r ans </dev/tty || true
    case $ans in y | Y | yes | YES) ;; *) die "cancelled" ;; esac
  fi
  step "Removing the OpenRoute server"
  if have systemctl; then systemctl disable --now "$SVC" >/dev/null 2>&1 || true; fi
  rm -f "$UNIT_FILE"
  if have systemctl; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
  ok "service removed"
  if [ -n "$FW_KIND" ] && [ -n "$FW_RULES" ]; then
    local r
    for r in $FW_RULES; do fw_close "$FW_KIND" "$r"; done
    fw_commit "$FW_KIND"
    ok "closed $FW_RULES in $FW_KIND"
  fi
  if [ -f "$SYSCTL_FILE" ]; then
    rm -f "$SYSCTL_FILE"
    ok "removed the BBR settings (they stay in effect until a reboot)"
  fi
  case $CONF_DIR in */$SVC) ;; *) die "internal error: refusing to remove $CONF_DIR" ;; esac
  rm -rf "$CONF_DIR" "$STATE_DIR"
  ok "removed ${CONF_DIR#"$ROOT"}"
  if getent passwd "$SVC_USER" >/dev/null 2>&1; then
    if userdel "$SVC_USER" >/dev/null 2>&1; then ok "removed system user $SVC_USER"; else warn "couldn't remove system user $SVC_USER"; fi
  fi
  if [ "$OPT_PURGE" = 1 ]; then
    purge_singbox
  else
    note "sing-box itself stays installed (add --purge to remove it)"
  fi
}

purge_singbox() {
  case $SB_SOURCE in
    repo)
      if have apt-get; then
        apt-get remove -y -qq sing-box </dev/null >/dev/null 2>&1 || warn "apt-get couldn't remove sing-box"
        rm -f "$APT_LIST" "$APT_KEY"
      elif have dnf || have yum; then
        local pm=yum
        have dnf && pm=dnf
        "$pm" -y -q remove sing-box </dev/null >/dev/null 2>&1 || warn "$pm couldn't remove sing-box"
        rm -f "$RPM_REPO" "$RPM_KEY"
      fi
      ok "removed sing-box and SagerNet's repository"
      ;;
    release)
      rm -f "$ROOT/usr/local/bin/sing-box"
      ok "removed /usr/local/bin/sing-box"
      ;;
    *) note "sing-box was installed before OpenRoute set up this server, so it stays" ;;
  esac
}

cmd_generate() {
  SYSTEM_MODE=0
  [ -n "$OPT_DIR" ] || die "generate needs --dir DIR"
  [[ $OPT_DIR != *$'\n'* ]] || die "--dir can't contain a newline"
  [ -n "$OPT_HOST" ] || die "generate needs --host (the address clients connect to)"
  [ "$OPT_SNI" != auto ] || die "generate doesn't test sites; pass --sni HOST"
  mkdir -p "$OPT_DIR"
  set_conf_dir "$OPT_DIR"
  find_singbox || die "no sing-box found; pass --sing-box PATH"
  local v
  v=$(sb_version "$SB")
  version_ge "$v" "$SB_MIN" || die "sing-box ${v:-?} is too old (need $SB_MIN or newer)"
  load_state || true
  apply_options
  HOST=$OPT_HOST HOST_AUTO=0
  [ -z "$OPT_SNI" ] || REALITY_SNI=$OPT_SNI
  [ -n "$REALITY_SNI" ] || REALITY_SNI=www.microsoft.com
  assign_ports
  new_credentials
  write_files
  cat "$LINKS_FILE"
}

main() {
  reset_state
  parse_args "$@"
  case $CMD in
    install) cmd_install ;;
    show) cmd_show ;;
    rotate) cmd_rotate ;;
    doctor) cmd_doctor ;;
    uninstall) cmd_uninstall ;;
    generate) cmd_generate ;;
  esac
}

# SagerNet's repository signing key: "Project S <contact@sagernet.org>",
# RSA 4096, fingerprint 2C31 7FBD 5D88 6B4E 89BA  E8DA 6D91 5217 2A2B 2F0C.
# The test suite checks this block's fingerprint, and that it verifies the
# signatures on deb.sagernet.org's InRelease and rpm.sagernet.org's repomd.xml.
sagernet_key() {
  cat <<'EOF'
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=U2h3
-----END PGP PUBLIC KEY BLOCK-----
EOF
}

main "$@"
