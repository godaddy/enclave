#!/usr/bin/env bash
# test-enclave-apps.sh — macOS test matrix for enclave apps
#
# Mirrors the structure of Test-EnclaveApps.ps1 (Windows). Auto-detects
# which apps are installed and runs CLI / agent / SSH / gitenc-signing
# coverage against each.
#
# Secure Enclave behaviour:
#   * On Apple Silicon (or T2-equipped Intel) the SE is available and
#     all default tests exercise it. SE-default keys generated without
#     `--require-user-presence` don't prompt for Touch ID, so they're
#     safe to run unattended in CI.
#   * `--require-user-presence` keys can only be exercised when a human
#     is at the keyboard to answer the LAContext / Touch ID prompt.
#     Those tests are gated behind `--interactive` / `$SSHENC_TEST_INTERACTIVE=1`
#     and skipped by default.
#   * On Intel without T2, SE isn't present; the default backend falls
#     back to software-on-disk and tests still run end-to-end (the
#     binaries' behaviour is identical from this script's point of view).
#
# Usage:
#   ./test-enclave-apps.sh                          # All installed apps, non-interactive
#   ./test-enclave-apps.sh sshenc                   # Only sshenc/gitenc
#   ./test-enclave-apps.sh awsenc sso-jwt           # Two apps
#   ./test-enclave-apps.sh --interactive            # Include Touch ID-prompted tests
#   ./test-enclave-apps.sh --skip-extended          # Skip agent/SSH/gitenc
#   ./test-enclave-apps.sh --software               # Force software backend (no SE)
#                                                   #   auto-enabled when CI=1 or
#                                                   #   GITHUB_ACTIONS=true is set

set -u
set +e  # we tally failures, don't abort on first

# ---- args -------------------------------------------------------------------
APPS=()
INTERACTIVE=0
SKIP_EXTENDED=0
USE_SOFTWARE=0

while [ $# -gt 0 ]; do
    case "$1" in
        -i|--interactive)
            INTERACTIVE=1
            ;;
        --skip-extended)
            SKIP_EXTENDED=1
            ;;
        --software)
            USE_SOFTWARE=1
            ;;
        -h|--help)
            sed -n '2,32p' "$0"
            exit 0
            ;;
        --*)
            echo "Unknown flag: $1" >&2
            exit 2
            ;;
        *)
            APPS+=("$1")
            ;;
    esac
    shift
done

if [ -n "${SSHENC_TEST_INTERACTIVE:-}" ] && [ "$SSHENC_TEST_INTERACTIVE" != "0" ]; then
    INTERACTIVE=1
fi

# CI environments default to software backend: the SE is present on
# Apple Silicon CI runners but has no enrolled biometric / passcode,
# so any keychain-touching op blocks waiting for a UI that never
# appears. SSHENC_FORCE_SOFTWARE=1 makes the binaries skip SE entirely.
if [ "$USE_SOFTWARE" = "1" ] || [ -n "${GITHUB_ACTIONS:-}" ] || [ -n "${CI:-}" ]; then
    export SSHENC_FORCE_SOFTWARE=1
fi

KNOWN_APPS=("awsenc" "sshenc" "sso-jwt" "npmenc")

# Auto-detect installed apps when none specified.
if [ ${#APPS[@]} -eq 0 ]; then
    for app in "${KNOWN_APPS[@]}"; do
        if command -v "$app" >/dev/null 2>&1; then
            APPS+=("$app")
        else
            echo "  [SKIP] $app - not installed"
        fi
    done
fi

if [ ${#APPS[@]} -eq 0 ]; then
    echo "No enclave apps installed; nothing to test." >&2
    exit 0
fi

# ---- platform detection -----------------------------------------------------

IS_APPLE_SILICON=0
if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = "1" ]; then
    IS_APPLE_SILICON=1
fi

# Best-effort SE-availability check. Apple Silicon → yes. Intel → likely
# T2 if it's a 2018+ Mac, but we don't try to detect T2 specifically;
# the binaries handle the fallback transparently.
HAS_SECURE_ENCLAVE=$IS_APPLE_SILICON

# ---- result tally -----------------------------------------------------------
PASS=0
FAIL=0
SKIP=0

C_GREEN=$(printf '\033[32m')
C_RED=$(printf '\033[31m')
C_YEL=$(printf '\033[33m')
C_CYA=$(printf '\033[36m')
C_WHT=$(printf '\033[37m')
C_GRY=$(printf '\033[90m')
C_END=$(printf '\033[0m')

record() {
    local status="$1" test="$2" detail="${3:-}"
    case "$status" in
        P) PASS=$((PASS + 1)); printf '  %s[PASS]%s %s' "$C_GREEN" "$C_END" "$test" ;;
        F) FAIL=$((FAIL + 1)); printf '  %s[FAIL]%s %s' "$C_RED"   "$C_END" "$test" ;;
        S) SKIP=$((SKIP + 1)); printf '  %s[SKIP]%s %s' "$C_YEL"   "$C_END" "$test" ;;
    esac
    if [ -n "$detail" ]; then
        printf ' %s- %s%s\n' "$C_GRY" "$detail" "$C_END"
    else
        printf '\n'
    fi
}

banner() {
    printf '\n%s========================================%s\n' "$C_CYA" "$C_END"
    printf '%s%s%s\n' "$C_CYA" "$1" "$C_END"
    printf '%s========================================%s\n' "$C_CYA" "$C_END"
}

section() {
    printf '\n  %s-- %s --%s\n' "$C_WHT" "$1" "$C_END"
}

# Run a command and PASS if it exits 0 and (optionally) stdout matches a regex.
test_cmd() {
    local name="$1" cmd="$2" expect="${3:-}"
    local out rc
    out=$(eval "$cmd" 2>&1)
    rc=$?
    if [ $rc -ne 0 ]; then
        local trim="${out%$'\n'}"
        record F "$name" "exit $rc: ${trim:0:120}"
        return
    fi
    if [ -n "$expect" ] && ! grep -qE "$expect" <<<"$out"; then
        local trim="${out%$'\n'}"
        record F "$name" "expected /$expect/, got: ${trim:0:120}"
        return
    fi
    record P "$name"
}

test_exit() {
    local name="$1" cmd="$2" expect_success="${3:-1}"
    eval "$cmd" >/dev/null 2>&1
    local rc=$?
    if [ "$expect_success" = "1" ] && [ $rc -eq 0 ]; then
        record P "$name"
    elif [ "$expect_success" = "0" ] && [ $rc -ne 0 ]; then
        record P "$name"
    else
        record F "$name" "exit $rc"
    fi
}

should_test() {
    local app="$1"
    for a in "${APPS[@]}"; do
        [ "$a" = "$app" ] && return 0
    done
    return 1
}

# Force-delete a sshenc key + .pub so we start clean. Verifies via
# `sshenc list` that the label is gone.
remove_sshenc_key() {
    local label="$1"
    local attempt list
    for attempt in 1 2 3; do
        : "$attempt"  # quiet shellcheck
        sshenc delete -y "$label" >/dev/null 2>&1
        rm -f "$HOME/.ssh/$label.pub"
        list=$(sshenc list 2>&1)
        if ! grep -qE "^$label\b" <<<"$list"; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

# ---- env summary ------------------------------------------------------------
banner "Environment"
echo "  macOS:       $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))"
echo "  arch:        $(arch)"
echo "  apple si:    $IS_APPLE_SILICON"
echo "  SE present:  $HAS_SECURE_ENCLAVE"
echo "  backend:     ${SSHENC_FORCE_SOFTWARE:+software (forced)}${SSHENC_FORCE_SOFTWARE:-secure-enclave}"
echo "  interactive: $INTERACTIVE"
echo "  apps:        ${APPS[*]}"

# ============================================================================
banner "macOS Shell Tests"
# ============================================================================

if should_test awsenc; then
    section awsenc
    test_cmd "awsenc --version"     "awsenc --version"           "awsenc"
    test_cmd "awsenc config"        "awsenc config"              "Config directory"
    test_cmd "awsenc list"          "awsenc list"
    test_exit "awsenc list --json"  "awsenc list --json"
    test_exit "awsenc clear --all"  "awsenc clear --all"
    test_cmd "awsenc shell-init bash" "awsenc shell-init bash"   "awsenc"
    test_cmd "awsenc shell-init zsh"  "awsenc shell-init zsh"    "awsenc"
    test_cmd "awsenc completions bash" "awsenc completions bash" "_awsenc"
fi

if should_test sshenc; then
    section sshenc
    test_cmd "sshenc --version"          "sshenc --version"          "sshenc"
    test_cmd "sshenc config path"        "sshenc config path"
    test_cmd "sshenc config show"        "sshenc config show"        "socket_path"
    test_cmd "sshenc list"               "sshenc list"
    test_cmd "sshenc completions bash"   "sshenc completions bash"   "_sshenc"
    test_cmd "sshenc completions zsh"    "sshenc completions zsh"    "compdef"

    # Key lifecycle. Two non-presence keys → distinct fingerprints,
    # listing/inspect/export-pub round-trip, then delete.
    tag="$(date +%H%M%S)-$RANDOM"
    keyA="test-key-a-$tag"
    keyB="test-key-b-$tag"
    if ! remove_sshenc_key "$keyA"; then record F "pre-clean $keyA" "still present after 3 deletes"; fi
    if ! remove_sshenc_key "$keyB"; then record F "pre-clean $keyB" "still present after 3 deletes"; fi

    # Use --no-user-presence so the SE key itself isn't gated by
    # Touch ID — the wrapping-key gate still fires once on first
    # access (cached for the next 5min), but subsequent test ops
    # in this run are silent.
    if sshenc keygen -l "$keyA" -C "test-a" --no-user-presence >/dev/null 2>&1; then
        record P "sshenc keygen $keyA"
    else
        record F "sshenc keygen $keyA"
    fi

    if sshenc keygen -l "$keyB" -C "test-b" --no-user-presence >/dev/null 2>&1; then
        record P "sshenc keygen $keyB"
    else
        record F "sshenc keygen $keyB"
    fi

    fpA=$(sshenc export-pub "$keyA" --fingerprint 2>&1)
    fpB=$(sshenc export-pub "$keyB" --fingerprint 2>&1)
    if grep -q "SHA256:" <<<"$fpA" && grep -q "SHA256:" <<<"$fpB" && [ "$fpA" != "$fpB" ]; then
        record P "keys have distinct fingerprints"
    else
        record F "keys have distinct fingerprints" "A=$fpA B=$fpB"
    fi

    test_cmd "sshenc inspect $keyA"     "sshenc inspect '$keyA'"     "ecdsa-p256"
    test_cmd "sshenc export-pub $keyA"  "sshenc export-pub '$keyA'"  "ecdsa-sha2-nistp256"

    if remove_sshenc_key "$keyA"; then record P "sshenc delete $keyA"; else record F "sshenc delete $keyA"; fi
    if remove_sshenc_key "$keyB"; then record P "sshenc delete $keyB"; else record F "sshenc delete $keyB"; fi

    # Presence-required key path: only run interactively. Generates
    # a key with --require-user-presence (Touch ID prompts on next
    # sign), exercises the LAContext cache window, and cleans up.
    if [ "$INTERACTIVE" = "1" ] && [ "$HAS_SECURE_ENCLAVE" = "1" ]; then
        keyP="test-key-presence-$tag"
        remove_sshenc_key "$keyP" >/dev/null 2>&1 || true

        if sshenc keygen -l "$keyP" -C "presence-test" --require-user-presence >/dev/null 2>&1; then
            record P "sshenc keygen --require-user-presence"

            # ssh-keygen-compat sign — exercises the SE sign path.
            tmpf=$(mktemp)
            printf "test signing payload\n" >"$tmpf"
            if sshenc -Y sign -n test -f "$HOME/.ssh/$keyP.pub" "$tmpf" >/dev/null 2>&1 \
                && [ -f "${tmpf}.sig" ]; then
                record P "sshenc -Y sign on presence-required key"
            else
                record F "sshenc -Y sign on presence-required key"
            fi
            rm -f "$tmpf" "${tmpf}.sig"
        else
            record F "sshenc keygen --require-user-presence"
        fi

        if remove_sshenc_key "$keyP"; then record P "sshenc delete $keyP"; else record F "sshenc delete $keyP"; fi
    elif [ "$HAS_SECURE_ENCLAVE" = "1" ]; then
        record S "presence-required key tests" "non-interactive run; rerun with --interactive"
    else
        record S "presence-required key tests" "no Secure Enclave on this host"
    fi
fi

if should_test npmenc; then
    section npmenc
    test_cmd "npmenc --version" "npmenc --version" "npmenc"
    test_cmd "npmenc --help"    "npmenc --help"    "npmenc"
    if command -v npxenc >/dev/null 2>&1; then
        test_cmd "npxenc --version" "npxenc --version" "npxenc"
    fi
fi

if should_test sso-jwt; then
    section sso-jwt
    test_cmd "sso-jwt --version"        "sso-jwt --version"        "sso-jwt"
    test_exit "sso-jwt --clear"         "sso-jwt --clear"
    test_cmd "sso-jwt shell-init bash"  "sso-jwt shell-init bash"  "sso-jwt"
    test_cmd "sso-jwt shell-init zsh"   "sso-jwt shell-init zsh"   "sso-jwt"
fi

# ============================================================================
if [ "$SKIP_EXTENDED" = "0" ] && should_test sshenc; then
    banner "Extended Tests (sshenc agent + SSH + gitenc signing)"

    # Stop any existing agent we own. Use a per-test socket so we
    # don't disturb the user's running ~/.sshenc/agent.sock.
    test_sock="$(mktemp -u "/tmp/test-enclave-sshenc.XXXXXX")"
    rm -f "$test_sock"
    sshenc agent --socket "$test_sock" >/dev/null 2>&1
    sleep 1

    if [ -S "$test_sock" ]; then
        record P "agent listening on Unix socket"
    else
        record F "agent listening on Unix socket" "socket not bound: $test_sock"
    fi

    section "Agent + SSH"
    if SSH_AUTH_SOCK="$test_sock" ssh-add -L 2>&1 | grep -q "ecdsa-sha2-nistp256"; then
        record P "agent key listing via Unix socket"
    else
        record F "agent key listing via Unix socket"
    fi

    # Live SSH to GitHub. Skipped automatically when offline / no
    # network access; we tag it as SKIP rather than FAIL so a
    # disconnected dev host doesn't fail the suite.
    if SSH_AUTH_SOCK="$test_sock" ssh -o BatchMode=yes -o ConnectTimeout=10 -T git@github.com 2>&1 \
        | grep -q "successfully authenticated"; then
        record P "SSH to GitHub via agent"
    else
        # Distinguish "network unreachable" from "auth failed":
        # ConnectTimeout failure is a SKIP, anything else is a FAIL.
        if ! ping -c 1 -t 3 github.com >/dev/null 2>&1; then
            record S "SSH to GitHub via agent" "no network"
        else
            record F "SSH to GitHub via agent" "auth failed"
        fi
    fi

    section "gitenc signing"
    test_dir="$(mktemp -d "/tmp/gitenc-shell-test.XXXXXX")"
    if SSH_AUTH_SOCK="$test_sock" git clone -q git@github.com:godaddy/sshenc.git "$test_dir" 2>/dev/null \
        && [ -d "$test_dir/.git" ]; then
        record P "git clone via SSH"

        (
            cd "$test_dir" || exit 1
            git config user.email "jgowdy@godaddy.com"
            git config user.name "Jay Gowdy"
            gitenc --config github-godaddy >/dev/null 2>&1 || true

            branch="test/shell-matrix-$(date +%Y%m%d%H%M%S)"
            git checkout -b "$branch" >/dev/null 2>&1
            printf "# shell matrix test %s\n" "$(date)" >>TESTING.md
            git add TESTING.md >/dev/null 2>&1

            commit_out=$(SSH_AUTH_SOCK="$test_sock" git commit -m "Test: shell matrix signed commit" 2>&1)
            if grep -qE "1 file changed|signed commit" <<<"$commit_out"; then
                record P "signed commit"
            else
                record F "signed commit" "$commit_out"
            fi

            sig_out=$(git log --show-signature -1 2>&1)
            if grep -qE "Good.*signature" <<<"$sig_out"; then
                record P "local signature verification"
            else
                record F "local signature verification" "$(head -3 <<<"$sig_out")"
            fi

            # Push + verify on GitHub side. Skipped offline.
            if SSH_AUTH_SOCK="$test_sock" git push -q origin "$branch" 2>/dev/null; then
                sleep 2
                gh_verify=$(gh api "repos/godaddy/sshenc/commits/$branch" --jq '.commit.verification.verified' 2>/dev/null)
                if [ "$gh_verify" = "true" ]; then
                    record P "GitHub signature verified"
                else
                    record F "GitHub signature verified" "got: $gh_verify"
                fi
                SSH_AUTH_SOCK="$test_sock" git push -q origin --delete "$branch" 2>/dev/null
            else
                record S "GitHub signature verified" "push failed; offline?"
            fi
        )
    else
        record S "git clone via SSH" "no network or auth not configured"
    fi
    rm -rf "$test_dir"

    section "sshenc install/uninstall"
    config_backup="$(mktemp "/tmp/ssh-config-backup.XXXXXX")"
    if [ -f "$HOME/.ssh/config" ]; then
        cp "$HOME/.ssh/config" "$config_backup"
    fi

    sshenc uninstall >/dev/null 2>&1
    if ! grep -q "sshenc" "$HOME/.ssh/config" 2>/dev/null; then
        record P "sshenc uninstall removes config"
    else
        record F "sshenc uninstall removes config"
    fi

    sshenc install >/dev/null 2>&1
    sleep 2
    if grep -q "IdentityAgent" "$HOME/.ssh/config" 2>/dev/null; then
        record P "sshenc install writes config"
    else
        record F "sshenc install writes config"
    fi

    # Restore the user's config exactly as it was.
    if [ -s "$config_backup" ]; then
        cp "$config_backup" "$HOME/.ssh/config"
    fi
    rm -f "$config_backup"

    # Tear down our test agent.
    pkill -f "sshenc-agent --socket $test_sock" 2>/dev/null || true
    rm -f "$test_sock"
fi

# ============================================================================
banner "Summary"

total=$((PASS + FAIL + SKIP))
printf '  %s%d pass%s, %s%d fail%s, %s%d skip%s (%d total)\n' \
    "$C_GREEN" "$PASS" "$C_END" \
    "$C_RED"   "$FAIL" "$C_END" \
    "$C_YEL"   "$SKIP" "$C_END" \
    "$total"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
