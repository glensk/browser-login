#!/bin/bash
# install.sh — install, update, uninstall or enrol the login broker (needs root).
#
# Layout (PLAN_login-broker.md 0.2):
#   _loginbroker                       role account (UID 450-499, no shell)
#   /var/db/login-broker               0700 _loginbroker   state, profiles, bw, bootstrap
#   /var/db/login-broker-run           0775 root:_loginbroker   socket dir (persistent:
#                                      macOS clears /var/run at boot)
#   /usr/local/libexec/login-broker    0755 root   releases/<id>, current -> release,
#                                      tools/uv, bin/bw, python (uv-managed), browsers
#   /var/log/login-broker.log          daemon output + install audit trail
#   /Library/LaunchDaemons/com.albert.login-broker.plist
#
# ROOT EXECUTES ONLY system binaries (/usr/bin, /bin, /usr/sbin, /sbin) and tools
# under LIBEXEC that this script downloaded itself against a pinned SHA-256.
# Nothing is resolved through PATH: ~/.local/bin and /opt/homebrew are writable by
# the agent uid. git runs as $SUDO_USER (never root: no repo hooks/config as root),
# and the code installed is `git archive <HEAD sha>`, not the working tree.
# tests/test_login_broker.py checks both rules against this file.
set -euo pipefail

# Clean environment: nothing from the caller's shell reaches root's tools.
if [[ -z "${LB_INSTALL_CLEAN_ENV:-}" ]]; then
	exec /usr/bin/env -i LB_INSTALL_CLEAN_ENV=1 HOME=/var/root \
		PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C TERM="${TERM:-dumb}" \
		SUDO_USER="${SUDO_USER:-}" /bin/bash "$0" "$@"
fi

# --- pinned tools (bump version + sha256 together; verify the sha upstream) ---
UV_VERSION="0.12.18"
UV_SHA256="cf40e0c6a202190ccd9e0406dcfdd5b2d6668a9a5c779b17948963df32aafe5b"
UV_URL="https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-aarch64-apple-darwin.tar.gz"
BW_VERSION="2026.9.0"
BW_SHA256="014bc4c093e586197013fac79b9d0f1df1da6004003293c8930406bf1ffde45b"
BW_URL="https://github.com/bitwarden/clients/releases/download/cli-v${BW_VERSION}/bw-macos-arm64-${BW_VERSION}.zip"

LABEL="com.albert.login-broker"
ROLE="_loginbroker"
HOME_DIR="/var/db/login-broker"
RUN_DIR="/var/db/login-broker-run"
LIBEXEC="/usr/local/libexec/login-broker"
UV="${LIBEXEC}/tools/uv/uv"
BW="${LIBEXEC}/bin/bw"
DOWNLOADS="${LIBEXEC}/.downloads"
LOG_FILE="/var/log/login-broker.log"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
SOCKET="${RUN_DIR}/broker.sock"
INVOKER="${SUDO_USER:-}"
[[ -n "$INVOKER" ]] || INVOKER="$(/usr/bin/id -un)"
INVOKER_HOME="$(/usr/bin/dscl . -read "/Users/${INVOKER}" NFSHomeDirectory | /usr/bin/awk '{print $2}')"
REPO_DIR="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DRY=0
PURGE=0
MODE="install"

usage() {
	/bin/cat <<'EOF'
Usage: sudo install/install.sh [-n] [-U [-P]] [-e] [-h]

Install (default), update, uninstall or enrol the login broker LaunchDaemon.
Refuses unless the repo is clean and HEAD is contained in origin/main; installs
`git archive HEAD` into a NEW release dir, swaps the `current` symlink
atomically, restarts the daemon and runs the boundary selfcheck as $SUDO_USER
(a failing selfcheck rolls back). The installed commit and the diffstat since
the previous one are appended to /var/log/login-broker.log.

Options:
  -n, --dry-run           print the actions only (no root needed)
  -U, --uninstall         stop the daemon, remove plist, code and socket dir
  -P, --purge             with -U: also delete /var/db/login-broker and the role account
  -e, --enroll-bootstrap  prompt (hidden) for the broker's Bitwarden API key,
                          master password and collection id; write
                          /var/db/login-broker/bootstrap.json (0600 _loginbroker)
  -h, --help              show this help and exit

Examples:
  install/install.sh -n          # preview an install
  sudo install/install.sh        # install / update
  sudo install/install.sh -e     # one-time Bitwarden enrolment
  sudo install/install.sh -U     # uninstall, keep state
  sudo install/install.sh -U -P  # uninstall and purge state + role account
EOF
}

die() {
	printf '❌ %s\n' "$*" >&2
	exit 1
}

# run CMD… — execute, or print it under --dry-run.
run() {
	if ((DRY)); then
		printf '+'
		printf ' %q' "$@"
		printf '\n'
	else
		"$@"
	fi
}

# as_user CMD… — run CMD as the invoking (non-root) user. Read-only commands
# only; it executes under --dry-run too.
as_user() {
	if ((EUID != 0)); then
		/usr/bin/env HOME="$INVOKER_HOME" "$@"
	else
		/usr/bin/sudo -H -u "$SUDO_USER" "$@"
	fi
}

while (($#)); do
	case "$1" in
	-h | --help)
		usage
		exit 0
		;;
	-n | --dry-run) DRY=1 ;;
	-U | --uninstall) MODE="uninstall" ;;
	-P | --purge) PURGE=1 ;;
	-e | --enroll-bootstrap) MODE="enroll" ;;
	*)
		usage >&2
		exit 2
		;;
	esac
	shift
done

if ((!DRY)) && ((EUID != 0)); then
	die "must run as root (sudo $0), or preview with -n"
fi
if ((EUID == 0)) && [[ -z "$SUDO_USER" || "$SUDO_USER" == "root" ]]; then
	die "run via sudo from the repo owner's account (git must not run as root)"
fi

# audit MSG — append one timestamped line to the log (the install audit trail).
audit() {
	if ((DRY)); then
		printf '+ audit: %s\n' "$*"
	else
		printf '%s install.sh: %s\n' "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$LOG_FILE"
	fi
}

# check_repo — clean tree and HEAD contained in origin/main; prints HEAD's sha.
check_repo() {
	local head dirty
	head="$(as_user /usr/bin/git -C "$REPO_DIR" rev-parse --verify HEAD)" ||
		die "cannot read HEAD of ${REPO_DIR}"
	# Untracked files cannot reach the install (it is `git archive HEAD`), so
	# only changes to tracked files block.
	dirty="$(as_user /usr/bin/git -C "$REPO_DIR" status --porcelain --untracked-files=no)"
	if [[ -n "$dirty" ]]; then
		((DRY)) || die "the repo working tree is not clean — commit or stash first"
		echo "⚠ would refuse: the repo working tree is not clean" >&2
	fi
	if ! as_user /usr/bin/git -C "$REPO_DIR" merge-base --is-ancestor "$head" origin/main; then
		((DRY)) || die "HEAD ${head} is not contained in origin/main — push it first"
		echo "⚠ would refuse: HEAD is not contained in origin/main" >&2
	fi
	printf '%s\n' "$head"
}

# free_role_id — first id in 450-499 (macOS role-account UID range) used
# neither as a UID nor as a GID.
free_role_id() {
	local used id
	used="$(
		/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '{print $2}'
		/usr/bin/dscl . -list /Groups PrimaryGroupID | /usr/bin/awk '{print $2}'
	)"
	for id in $(/usr/bin/seq 450 499); do
		if ! /usr/bin/grep -qx "$id" <<<"$used"; then
			echo "$id"
			return 0
		fi
	done
	return 1
}

# role_uid — the role account's UniqueID; fails when it has none (dscl exits 0
# on a missing key, so the output is what counts).
role_uid() {
	/usr/bin/dscl . -read "/Users/${ROLE}" UniqueID 2>/dev/null |
		/usr/bin/awk '$1 == "UniqueID:" { print $2; found = 1 } END { exit !found }'
}

ensure_role_account() {
	if role_uid >/dev/null; then
		echo "✓ role account ${ROLE} exists"
		return 0
	fi
	# A record without UniqueID is the remnant of an interrupted create.
	if /usr/bin/dscl . -read "/Users/${ROLE}" >/dev/null 2>&1; then
		run /usr/bin/dscl . -delete "/Users/${ROLE}"
	fi
	local id gid
	if ((DRY)); then
		id="<free id 450-499>"
	else
		id="$(free_role_id)" || die "no free UID/GID in 450-499"
	fi
	# A group left by an earlier, failed run is reused with its own GID.
	gid="$(/usr/bin/dscl . -read "/Groups/${ROLE}" PrimaryGroupID 2>/dev/null |
		/usr/bin/awk '{print $2}')"
	if [[ -z "$gid" ]]; then
		gid="$id"
		run /usr/sbin/dseditgroup -o create -i "$gid" -r "login broker" "$ROLE"
	fi
	run /usr/sbin/sysadminctl -addUser "$ROLE" -UID "$id" -roleAccount \
		-home "$HOME_DIR" -shell /usr/bin/false -fullName "login broker"
	# sysadminctl exits 0 even when it refuses, so verify the account exists.
	if ! ((DRY)) && ! role_uid >/dev/null; then
		die "sysadminctl did not create ${ROLE} (see its message above)"
	fi
	run /usr/bin/dscl . -create "/Users/${ROLE}" PrimaryGroupID "$gid"
	run /usr/sbin/dseditgroup -o edit -a "$ROLE" -t user "$ROLE"
}

ensure_dirs() {
	run /usr/bin/install -d -o "$ROLE" -g "$ROLE" -m 0700 "$HOME_DIR"
	run /usr/bin/install -d -o "$ROLE" -g "$ROLE" -m 0700 "${HOME_DIR}/profiles"
	run /usr/bin/install -d -o "$ROLE" -g "$ROLE" -m 0700 "${HOME_DIR}/bw"
	run /usr/bin/install -d -o root -g wheel -m 0755 "$LIBEXEC"
	local d
	for d in releases browsers python bin tools tools/uv; do
		run /usr/bin/install -d -o root -g wheel -m 0755 "${LIBEXEC}/${d}"
	done
	run /usr/bin/install -d -o root -g wheel -m 0700 "$DOWNLOADS"
	# Group-writable so the daemon (role account) can create its socket; others
	# may only connect (the peer-uid check is the gate).
	run /usr/bin/install -d -o root -g "$ROLE" -m 0775 "$RUN_DIR"
	if ((DRY)) || [[ ! -e "$LOG_FILE" ]]; then
		run /usr/bin/install -o "$ROLE" -g admin -m 0640 /dev/null "$LOG_FILE"
	fi
}

# fetch_verified URL SHA256 DEST — download over HTTPS and check the pinned hash.
fetch_verified() {
	local url="$1" sha="$2" dest="$3"
	run /usr/bin/curl -fsSL --proto '=https' --tlsv1.2 -o "$dest" "$url"
	if ((DRY)); then
		printf '+ verify sha256 %s %s\n' "$sha" "$dest"
		return 0
	fi
	printf '%s  %s\n' "$sha" "$dest" | /usr/bin/shasum -a 256 -c - >/dev/null ||
		{
			/bin/rm -f "$dest"
			die "SHA-256 mismatch for ${url}"
		}
}

# ensure_uv / ensure_bw — pinned standalone binaries, re-fetched when the pin moves.
ensure_uv() {
	if [[ "$(/bin/cat "${LIBEXEC}/tools/uv/.sha256" 2>/dev/null || true)" == "$UV_SHA256" && -x "$UV" ]]; then
		return 0
	fi
	fetch_verified "$UV_URL" "$UV_SHA256" "${DOWNLOADS}/uv.tar.gz"
	run /usr/bin/tar -xzf "${DOWNLOADS}/uv.tar.gz" -C "${LIBEXEC}/tools/uv" \
		--strip-components 1
	run /usr/sbin/chown -R root:wheel "${LIBEXEC}/tools/uv"
	run /bin/chmod 0755 "$UV"
	((DRY)) || printf '%s\n' "$UV_SHA256" >"${LIBEXEC}/tools/uv/.sha256"
	audit "uv ${UV_VERSION} sha256 ${UV_SHA256}"
}

ensure_bw() {
	if [[ "$(/bin/cat "${LIBEXEC}/bin/.bw.sha256" 2>/dev/null || true)" == "$BW_SHA256" && -x "$BW" ]]; then
		return 0
	fi
	fetch_verified "$BW_URL" "$BW_SHA256" "${DOWNLOADS}/bw.zip"
	run /bin/rm -rf "${DOWNLOADS}/bw"
	run /usr/bin/unzip -q -o "${DOWNLOADS}/bw.zip" -d "${DOWNLOADS}/bw"
	run /usr/bin/install -o root -g wheel -m 0755 "${DOWNLOADS}/bw/bw" "$BW"
	((DRY)) || printf '%s\n' "$BW_SHA256" >"${LIBEXEC}/bin/.bw.sha256"
	audit "bw ${BW_VERSION} sha256 ${BW_SHA256}"
}

# install_release DIR HEAD — `git archive HEAD` + hash-locked venv + Chromium.
install_release() {
	local rel="$1" head="$2"
	run /usr/bin/install -d -o root -g wheel -m 0755 "$rel"
	# The archive is produced as the user (git never runs as root) and only
	# unpacked as root; it is exactly the audited commit, not the work tree.
	if ((DRY)); then
		printf '+ /usr/bin/sudo -H -u %s /usr/bin/git -C %q archive %s broker pyproject.toml uv.lock | /usr/bin/tar -xf - -C %q\n' \
			"$INVOKER" "$REPO_DIR" "$head" "$rel"
	else
		as_user /usr/bin/git -C "$REPO_DIR" archive --format=tar "$head" \
			broker pyproject.toml uv.lock | /usr/bin/tar -xf - -C "$rel"
		printf '%s\n' "$head" >"${rel}/COMMIT"
	fi
	# Interpreter under LIBEXEC (root-owned), never in a user's ~/.local/share/uv:
	# a user-writable interpreter would be code execution as the role account.
	run /usr/bin/env UV_PYTHON_INSTALL_DIR="${LIBEXEC}/python" \
		UV_PYTHON_PREFERENCE=only-managed UV_CACHE_DIR="${LIBEXEC}/.uv-cache" \
		UV_NO_CONFIG=1 "$UV" venv --python 3.12 "${rel}/venv"
	# Dependencies exactly as locked in uv.lock, wheel hashes enforced.
	run /usr/bin/env UV_CACHE_DIR="${LIBEXEC}/.uv-cache" UV_NO_CONFIG=1 \
		"$UV" export --frozen --no-dev --no-emit-project --format requirements-txt \
		--project "$rel" -o "${rel}/requirements.txt"
	run /usr/bin/env UV_CACHE_DIR="${LIBEXEC}/.uv-cache" UV_NO_CONFIG=1 \
		"$UV" pip install --python "${rel}/venv/bin/python" --require-hashes \
		-r "${rel}/requirements.txt"
	run /usr/bin/env PLAYWRIGHT_BROWSERS_PATH="${LIBEXEC}/browsers" \
		"${rel}/venv/bin/python" -m playwright install chromium
	run /usr/sbin/chown -R root:wheel "$rel" "${LIBEXEC}/python" "${LIBEXEC}/browsers"
	run /bin/chmod -R go-w "$rel" "${LIBEXEC}/python" "${LIBEXEC}/browsers"
}

write_plist() {
	local tmp
	tmp="$(/usr/bin/mktemp "/tmp/login-broker-plist.XXXXXX")"
	/bin/cat >"$tmp" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>${LABEL}</string>
	<key>UserName</key>
	<string>${ROLE}</string>
	<key>GroupName</key>
	<string>${ROLE}</string>
	<key>ProgramArguments</key>
	<array>
		<string>${LIBEXEC}/current/venv/bin/python</string>
		<string>${LIBEXEC}/current/broker/daemon.py</string>
		<string>--socket</string>
		<string>${SOCKET}</string>
		<string>--home</string>
		<string>${HOME_DIR}</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>HOME</key>
		<string>${HOME_DIR}</string>
		<key>PLAYWRIGHT_BROWSERS_PATH</key>
		<string>${LIBEXEC}/browsers</string>
		<key>PATH</key>
		<string>${LIBEXEC}/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
	</dict>
	<key>WorkingDirectory</key>
	<string>${HOME_DIR}</string>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>StandardOutPath</key>
	<string>${LOG_FILE}</string>
	<key>StandardErrorPath</key>
	<string>${LOG_FILE}</string>
</dict>
</plist>
EOF
	if ((DRY)); then
		echo "= write ${PLIST}:"
		/usr/bin/sed 's/^/    /' "$tmp"
		/bin/rm -f "$tmp"
		return 0
	fi
	/usr/bin/plutil -lint "$tmp" >/dev/null || die "generated plist does not lint"
	/usr/bin/install -o root -g wheel -m 0644 "$tmp" "$PLIST"
	/bin/rm -f "$tmp"
}

# swap_current TARGET — atomically point LIBEXEC/current at TARGET (rename(2)).
swap_current() {
	local target="$1"
	run /bin/ln -sfn "$target" "${LIBEXEC}/current.new"
	run "${target}/venv/bin/python" -c \
		'import os, sys; os.replace(sys.argv[1], sys.argv[2])' \
		"${LIBEXEC}/current.new" "${LIBEXEC}/current"
}

# bootout — stop the daemon if it is loaded (quiet when it is not).
bootout() {
	if ((DRY)); then
		run /bin/launchctl bootout "system/${LABEL}"
	else
		/bin/launchctl bootout "system/${LABEL}" 2>/dev/null || true
		# bootout returns before the service is gone; a bootstrap in that window
		# fails with "5: Input/output error", so wait until launchd forgot it.
		for _ in $(/usr/bin/seq 1 40); do
			/bin/launchctl print "system/${LABEL}" >/dev/null 2>&1 || return 0
			/bin/sleep 0.25
		done
	fi
}

restart_daemon() {
	bootout
	if ((DRY)); then
		run /bin/launchctl bootstrap system "$PLIST"
		return 0
	fi
	local try
	for try in 1 2 3 4 5; do
		echo "+ /bin/launchctl bootstrap system ${PLIST}"
		/bin/launchctl bootstrap system "$PLIST" && return 0
		echo "  bootstrap attempt ${try} failed; retrying"
		/bin/sleep 1
	done
	die "launchctl bootstrap kept failing; try: sudo /bin/launchctl bootstrap system ${PLIST}"
}

wait_for_socket() {
	((DRY)) && return 0
	for _ in $(/usr/bin/seq 1 30); do
		[[ -S "$SOCKET" ]] && return 0
		/bin/sleep 0.5
	done
	return 1
}

run_selfcheck() {
	run /usr/bin/sudo -u "$INVOKER" "${LIBEXEC}/current/venv/bin/python" \
		"${LIBEXEC}/current/broker/selfcheck.py" -b
}

# audit_install HEAD PREVIOUS_RELEASE — what code just went root-owned.
audit_install() {
	local head="$1" previous="$2" prev_commit="" stat
	if [[ -n "$previous" && -r "${previous}/COMMIT" ]]; then
		prev_commit="$(/bin/cat "${previous}/COMMIT")"
	fi
	audit "installed commit ${head} (previous ${prev_commit:-none})"
	if [[ -n "$prev_commit" ]]; then
		stat="$(as_user /usr/bin/git -C "$REPO_DIR" diff --stat "${prev_commit}..${head}" 2>&1 ||
			echo "(diffstat unavailable)")"
		while IFS= read -r line; do
			audit "  ${line}"
		done <<<"$stat"
	fi
}

do_install() {
	local head rel previous=""
	[[ "$(/usr/bin/uname -m)" == "arm64" ]] || die "pinned tools are arm64-only"
	head="$(check_repo)"
	ensure_role_account
	ensure_dirs
	ensure_uv
	ensure_bw
	rel="${LIBEXEC}/releases/${head:0:12}-$(/bin/date -u +%Y%m%dT%H%M%SZ)"
	install_release "$rel" "$head"
	if [[ -L "${LIBEXEC}/current" ]]; then
		previous="$(/usr/bin/readlink "${LIBEXEC}/current")"
	fi
	write_plist
	swap_current "$rel"
	restart_daemon
	if ! wait_for_socket || ! run_selfcheck; then
		if [[ -n "$previous" ]]; then
			echo "❌ selfcheck failed — rolling back to ${previous}" >&2
			swap_current "$previous"
			restart_daemon
		fi
		audit "install of ${head} FAILED its selfcheck (rolled back: ${previous:-nothing})"
		die "install of ${rel} failed its selfcheck"
	fi
	if [[ -n "$previous" ]]; then
		run /bin/ln -sfn "$previous" "${LIBEXEC}/previous"
	fi
	audit_install "$head" "$previous"
	echo "✓ login broker installed: ${rel}"
}

do_uninstall() {
	bootout
	run /bin/rm -f "$PLIST"
	run /bin/rm -rf "$LIBEXEC"
	run /bin/rm -rf "$RUN_DIR"
	if ((PURGE)); then
		run /bin/rm -rf "$HOME_DIR"
		if /usr/bin/dscl . -read "/Users/${ROLE}" >/dev/null 2>&1; then
			run /usr/sbin/sysadminctl -deleteUser "$ROLE"
		fi
		if /usr/bin/dscl . -read "/Groups/${ROLE}" >/dev/null 2>&1; then
			run /usr/sbin/dseditgroup -o delete "$ROLE"
		fi
	else
		echo "ℹ kept ${HOME_DIR} and the ${ROLE} account (purge with -U -P)"
	fi
	audit "uninstalled (purge=${PURGE})"
	echo "✓ login broker uninstalled"
}

# Secrets are read hidden from the terminal and handed to the JSON writer via
# the environment (never argv); nothing is echoed.
do_enroll() {
	local py="${LIBEXEC}/current/venv/bin/python" tmp
	if ((DRY)); then
		echo "= prompt (hidden): BW client_id, client_secret, master password; collection id"
		echo "= write ${HOME_DIR}/bootstrap.json (0600 ${ROLE})"
		return 0
	fi
	[[ -x "$py" ]] || die "install the broker first (no ${py})"
	[[ -d "$HOME_DIR" ]] || die "install the broker first (no ${HOME_DIR})"
	local bw_client_id bw_client_secret bw_master collection_id
	read -rs -p "Broker Bitwarden client_id: " bw_client_id </dev/tty
	echo
	read -rs -p "Broker Bitwarden client_secret: " bw_client_secret </dev/tty
	echo
	read -rs -p "Broker Bitwarden master password: " bw_master </dev/tty
	echo
	read -rs -p "agent-logins collection id: " collection_id </dev/tty
	echo
	[[ -n "$bw_client_id" && -n "$bw_client_secret" && -n "$bw_master" && -n "$collection_id" ]] ||
		die "all four values are required"
	tmp="$(umask 077 && /usr/bin/mktemp "${HOME_DIR}/.bootstrap.XXXXXX")"
	LB_CID="$bw_client_id" LB_CSECRET="$bw_client_secret" LB_MASTER="$bw_master" \
		LB_COLL="$collection_id" "$py" -c '
import json, os, sys
data = {
    "client_id": os.environ["LB_CID"],
    "client_secret": os.environ["LB_CSECRET"],
    "master_password": os.environ["LB_MASTER"],
    "collection_id": os.environ["LB_COLL"],
}
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(data, fh)
    fh.flush()
    os.fsync(fh.fileno())
' "$tmp"
	unset bw_client_id bw_client_secret bw_master collection_id
	/usr/sbin/chown "${ROLE}:${ROLE}" "$tmp"
	/bin/chmod 0600 "$tmp"
	/bin/mv -f "$tmp" "${HOME_DIR}/bootstrap.json"
	audit "bootstrap.json (re)enrolled"
	echo "✓ wrote ${HOME_DIR}/bootstrap.json (0600 ${ROLE})"
}

case "$MODE" in
install) do_install ;;
uninstall) do_uninstall ;;
enroll) do_enroll ;;
esac
