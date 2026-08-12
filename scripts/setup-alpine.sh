#!/bin/sh
# setup-alpine.sh — install net-scanner as a background OpenRC service on Alpine Linux.
# All settings are passed to the app as command-line parameters (no config file).
#
# Usage:
#   sudo ./setup-alpine.sh ./net-scanner    # install a pre-built musl binary
#   sudo ./setup-alpine.sh                  # build from ./ source (run from repo root)
# Aborts unless the host is Alpine Linux.

set -eu

# --- Settings (edit these) -------------------------------------------------
BIND="0.0.0.0:8080"
SUBNETS="192.168.100.0/24"      # space-separated CIDRs; empty = auto-detect
INTERVAL="10"
METHOD="auto"
# ---------------------------------------------------------------------------

BIN_SRC="${1:-}"
INSTALL_BIN="/usr/local/bin/net-scanner"
INIT="/etc/init.d/net-scanner"
LOG="/var/log/net-scanner.log"

die() { echo "ERROR: $*" >&2; exit 1; }

is_alpine=0
[ -f /etc/alpine-release ] && is_alpine=1
[ "$is_alpine" -eq 0 ] && command -v apk >/dev/null 2>&1 && is_alpine=1
[ "$is_alpine" -eq 1 ] || die "Not Alpine Linux (no /etc/alpine-release and no apk). Aborting."
echo "==> Alpine Linux detected"

[ "$(id -u)" -eq 0 ] || die "Please run as root (e.g. sudo $0 ...)"

# --- Binary ---------------------------------------------------------------
if [ -n "$BIN_SRC" ] && [ -f "$BIN_SRC" ]; then
    echo "==> Installing binary from $BIN_SRC"
    install -m 0755 "$BIN_SRC" "$INSTALL_BIN"
elif [ -x "$INSTALL_BIN" ]; then
    echo "==> Using existing binary at $INSTALL_BIN"
elif [ -f Cargo.toml ]; then
    echo "==> Installing Rust toolchain and building release binary"
    apk add --no-cache cargo rust build-base musl-dev
    cargo build --release
    install -m 0755 target/release/net-scanner "$INSTALL_BIN"
else
    die "No binary found. Pass one as \$1 or run from the repo root."
fi

# Smoke test: catches a glibc binary that cannot run on Alpine's musl.
"$INSTALL_BIN" --version >/dev/null 2>&1 \
    || die "Installed binary does not run here (wrong libc/arch?)."

# --- Build parameter list ---------------------------------------------------
ARGS="--bind $BIND --interval $INTERVAL --method $METHOD"
for s in $SUBNETS; do
    ARGS="$ARGS --subnet $s"
done

# --- Init script -------------------------------------------------------------
cat > "$INIT" <<EOF
#!/sbin/openrc-run

description="LAN IP scanner with a web UI"
supervisor="supervise-daemon"
command="$INSTALL_BIN"
command_args="$ARGS"
command_user="root"
pidfile="/run/\${RC_SVCNAME}.pid"
output_log="$LOG"
error_log="$LOG"
respawn_delay=5

depend() {
    need net
    after firewall
}
EOF
chmod +x "$INIT"
echo "==> Wrote $INIT"

# --- Enable + start ------------------------------------------------------------
command -v rc-service >/dev/null 2>&1 || apk add --no-cache openrc
rc-update add net-scanner default 2>/dev/null || true
rc-service net-scanner restart
sleep 2

rc-service net-scanner status || true
if command -v curl >/dev/null 2>&1; then
    ok=$(curl -fsS http://127.0.0.1:8080/api/health >/dev/null 2>&1 && echo yes || echo no)
else
    ok=$(wget -q -O /dev/null http://127.0.0.1:8080/api/health && echo yes || echo no)
fi
if [ "$ok" = yes ]; then
    echo "OK: net-scanner is running. Open http://<server-ip>:8080"
else
    echo "WARNING: health check failed — see $LOG" >&2
fi
echo "Manage: rc-service net-scanner {start|stop|restart|status}   Logs: tail -f $LOG"
