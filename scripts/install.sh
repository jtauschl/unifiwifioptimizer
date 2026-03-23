#!/bin/sh

set -eu

REPO_OWNER="${REPO_OWNER:-jtauschl}"
REPO_NAME="${REPO_NAME:-unifiwifioptimizer}"
REPO_REF="${REPO_REF:-main}"
RAW_BASE="${RAW_BASE:-https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_REF}}"

INSTALL_ROOT="${INSTALL_ROOT:-${HOME}/.local/share/unifiwifioptimizer}"
BIN_DIR="${BIN_DIR:-${HOME}/.local/bin}"
CMD_NAME="${CMD_NAME:-unifiwifioptimizer}"
UNINSTALL_NAME="${UNINSTALL_NAME:-unifiwifioptimizer-uninstall}"
PROMPT_INPUT="${PROMPT_INPUT:-/dev/tty}"
PROMPT_OUTPUT="${PROMPT_OUTPUT:-/dev/tty}"
INTERACTIVE_SETUP="${INTERACTIVE_SETUP:-auto}"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'ERROR: Missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

download_file() {
  src_path="$1"
  dest_path="$2"

  mkdir -p "$(dirname "$dest_path")"
  curl -fsSL "${RAW_BASE}/${src_path}" -o "$dest_path"
}

require_command curl
require_command chmod
require_command mkdir
require_command cp
require_command sed

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT INT TERM

has_prompt_io() {
  [ -r "$PROMPT_INPUT" ] && [ -w "$PROMPT_OUTPUT" ]
}

tty_print() {
  printf '%s' "$1" >> "$PROMPT_OUTPUT"
}

tty_println() {
  printf '%s\n' "$1" >> "$PROMPT_OUTPUT"
}

prompt_line() {
  prompt="$1"
  default_value="${2:-}"
  answer=""

  if [ -n "$default_value" ]; then
    tty_print "$prompt [$default_value]: "
  else
    tty_print "$prompt: "
  fi

  IFS= read -r answer <&3 || answer=""
  if [ -z "$answer" ]; then
    answer="$default_value"
  fi
  printf '%s' "$answer"
}

prompt_secret() {
  prompt="$1"
  answer=""

  tty_print "$prompt: "
  if [ "$PROMPT_INPUT" = "/dev/tty" ] && [ -r /dev/tty ]; then
    stty -echo < /dev/tty
    IFS= read -r answer <&3 || answer=""
    stty echo < /dev/tty
    tty_println ""
  else
    IFS= read -r answer <&3 || answer=""
  fi
  printf '%s' "$answer"
}

prompt_yes_no() {
  prompt="$1"
  default_answer="${2:-n}"
  answer=""

  case "$default_answer" in
    y|Y) suffix='[Y/n]' ;;
    *) suffix='[y/N]' ;;
  esac

  tty_print "$prompt $suffix "
  IFS= read -r answer <&3 || answer=""
  case "${answer:-$default_answer}" in
    y|Y|yes|YES|Yes) return 0 ;;
    *) return 1 ;;
  esac
}

write_controller_config() {
  controller_url="$1"
  controller_api_key="$2"
  dest_path="$3"
  escaped_url=$(printf '%s' "$controller_url" | sed 's/\\/\\\\/g; s/"/\\"/g')
  escaped_api_key=$(printf '%s' "$controller_api_key" | sed 's/\\/\\\\/g; s/"/\\"/g')

  cat > "$dest_path" <<EOF
controller:
  url: "$escaped_url"
  api_key: "$escaped_api_key"
EOF
}

backup_config_if_present() {
  config_path="$1"
  if [ -f "$config_path" ]; then
    backup_path="${config_path}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$config_path" "$backup_path"
    tty_println "Backed up existing config to $backup_path"
  fi
}

extract_default_ssh_user() {
  skeleton_path="$1"
  python3 - "$skeleton_path" <<'PY'
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    for line in handle:
        stripped = line.strip()
        if stripped.startswith("user:"):
            print(stripped.split(":", 1)[1].strip().strip('"'))
            break
PY
}

extract_ap_names() {
  skeleton_path="$1"
  python3 - "$skeleton_path" <<'PY'
import sys

path = sys.argv[1]
inside = False
with open(path, "r", encoding="utf-8") as handle:
    for line in handle:
        if line.startswith("    neighbors:"):
            inside = True
            continue
        if inside:
          if not line.startswith("      "):
            break
          stripped = line.strip()
          if ":" in stripped:
            print(stripped.split(":", 1)[0].strip().strip('"'))
PY
}

edit_site_skeleton() {
  skeleton_path="$1"
  ssh_user="$2"
  ssh_password="$3"
  neighbor_spec_path="$4"

  python3 - "$skeleton_path" "$ssh_user" "$ssh_password" "$neighbor_spec_path" <<'PY'
import sys

skeleton_path, ssh_user, ssh_password, neighbor_spec_path = sys.argv[1:]

def yaml_scalar(value):
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'

neighbors = {}
with open(neighbor_spec_path, "r", encoding="utf-8") as handle:
    for raw_line in handle:
        line = raw_line.rstrip("\n")
        if not line:
            continue
        ap, values = line.split("\t", 1)
        neighbors[ap] = [item for item in values.split(",") if item]

with open(skeleton_path, "r", encoding="utf-8") as handle:
    lines = handle.readlines()

updated = []
inside_neighbors = False
for line in lines:
    stripped = line.strip()

    if stripped.startswith("user:"):
        indent = line[: len(line) - len(line.lstrip())]
        updated.append(f"{indent}user: {yaml_scalar(ssh_user)}\n")
        continue

    if "password: YOUR_SSH_PASSWORD" in stripped:
        if ssh_password:
            indent = line[: len(line) - len(line.lstrip())]
            updated.append(f"{indent}password: {yaml_scalar(ssh_password)}\n")
        continue

    if stripped == "neighbors:":
        inside_neighbors = True
        updated.append(line)
        continue

    if inside_neighbors:
        if not line.startswith("      "):
            inside_neighbors = False
            updated.append(line)
            continue

        ap_name = stripped.split(":", 1)[0].strip().strip('"')
        values = neighbors.get(ap_name, [])
        key_prefix = line.split(":", 1)[0]
        rendered = ", ".join(yaml_scalar(value) for value in values)
        updated.append(f"{key_prefix}: [{rendered}]\n")
        continue

    updated.append(line)

with open(skeleton_path, "w", encoding="utf-8") as handle:
    handle.writelines(updated)
PY
}

run_optional_setup() {
  config_path="$INSTALL_ROOT/config.yaml"
  controller_url=""
  controller_api_key=""
  site_id=""
  ssh_user=""
  ssh_password=""
  skeleton_path="${tmpdir}/site-skeleton.yaml"
  neighbor_spec_path="${tmpdir}/neighbors.tsv"
  ap_names_path="${tmpdir}/ap-names.txt"

  case "$INTERACTIVE_SETUP" in
    0|false|False|FALSE|no|No|NO)
      return 0
      ;;
  esac

  if ! has_prompt_io; then
    if [ "$INTERACTIVE_SETUP" = "auto" ]; then
      return 0
    fi
    printf 'WARNING: Interactive setup requested, but no TTY is available.\n' >&2
    return 0
  fi

  exec 3< "$PROMPT_INPUT"

  if ! prompt_yes_no "Create or update config.yaml now?" y; then
    return 0
  fi

  controller_url=$(prompt_line "UniFi controller URL" "https://unifi")
  while :; do
    controller_api_key=$(prompt_secret "UniFi API key")
    if [ -n "$controller_api_key" ]; then
      break
    fi
    tty_println "An API key is required."
  done

  backup_config_if_present "$config_path"
  write_controller_config "$controller_url" "$controller_api_key" "$config_path"
  tty_println "Wrote controller settings to $config_path"

  if ! prompt_yes_no "Try connecting now and list available sites?" y; then
    return 0
  fi

  if ! command -v bash >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1 || ! command -v ruby >/dev/null 2>&1 || ! command -v ssh >/dev/null 2>&1; then
    tty_println "Skipping site discovery because required runtime commands are missing."
    return 0
  fi

  tty_println ""
  tty_println "Available sites:"
  if ! "$INSTALL_ROOT/unifiwifioptimizer" --sites > "$tmpdir/sites.out" 2> "$tmpdir/sites.err"; then
    cat "$tmpdir/sites.err" >> "$PROMPT_OUTPUT"
    tty_println "Skipping site setup."
    return 0
  fi
  cat "$tmpdir/sites.out" >> "$PROMPT_OUTPUT"

  if ! prompt_yes_no "Generate a site config now?" n; then
    return 0
  fi

  site_id=$(prompt_line "Site ID to configure" "")
  if [ -z "$site_id" ]; then
    tty_println "No site selected. Keeping controller-only config."
    return 0
  fi

  if ! "$INSTALL_ROOT/unifiwifioptimizer" --config "$site_id" > "$skeleton_path" 2> "$tmpdir/config.err"; then
    cat "$tmpdir/config.err" >> "$PROMPT_OUTPUT"
    tty_println "Keeping controller-only config."
    return 0
  fi

  tty_println ""
  tty_println "Access points in $site_id:"
  extract_ap_names "$skeleton_path" > "$ap_names_path"
  sed 's/^/  - /' "$ap_names_path" > "$tmpdir/ap-list.txt"
  cat "$tmpdir/ap-list.txt" >> "$PROMPT_OUTPUT"

  ssh_user=$(extract_default_ssh_user "$skeleton_path")
  ssh_user=$(prompt_line "SSH user" "${ssh_user:-YOUR_SSH_USER}")

  if prompt_yes_no "Store an SSH password in config.yaml?" n; then
    ssh_password=$(prompt_secret "SSH password")
  fi

  : > "$neighbor_spec_path"
  if prompt_yes_no "Configure AP neighbors now?" n; then
    tty_println ""
    # shellcheck disable=SC2094
    while IFS= read -r ap_name; do
      [ -n "$ap_name" ] || continue
      while :; do
        neighbors=$(prompt_line "Neighbors for ${ap_name} (comma-separated, blank for none)" "")
        if [ -z "$neighbors" ]; then
          printf '%s\t\n' "$ap_name" >> "$neighbor_spec_path"
          break
        fi
        validation=$(AP_NAMES_PATH="$ap_names_path" NEIGHBORS="$neighbors" python3 - <<'PY'
import os

with open(os.environ["AP_NAMES_PATH"], "r", encoding="utf-8") as handle:
    aps = {line.rstrip("\n") for line in handle if line.strip()}
neighbors = [item.strip() for item in os.environ["NEIGHBORS"].split(",") if item.strip()]
invalid = [item for item in neighbors if item not in aps]
print(",".join(invalid))
print(",".join(neighbors))
PY
)
        invalid=$(printf '%s\n' "$validation" | sed -n '1p')
        normalized=$(printf '%s\n' "$validation" | sed -n '2p')
        if [ -n "$invalid" ]; then
          tty_println "Unknown AP name(s): $invalid"
          tty_println "Use the listed AP names exactly."
          continue
        fi
        printf '%s\t%s\n' "$ap_name" "$normalized" >> "$neighbor_spec_path"
        break
      done
    done < "$ap_names_path"
  else
    while IFS= read -r ap_name; do
      [ -n "$ap_name" ] && printf '%s\t\n' "$ap_name" >> "$neighbor_spec_path"
    done < "$ap_names_path"
  fi

  edit_site_skeleton "$skeleton_path" "$ssh_user" "$ssh_password" "$neighbor_spec_path"
  printf '\n' >> "$config_path"
  cat "$skeleton_path" >> "$config_path"
  tty_println "Wrote site configuration for $site_id to $config_path"
}

download_file "unifiwifioptimizer" "${tmpdir}/unifiwifioptimizer"
download_file "profiles.yaml" "${tmpdir}/profiles.yaml"
download_file "config.minimal.yaml" "${tmpdir}/config.minimal.yaml"
download_file "config.example.yaml" "${tmpdir}/config.example.yaml"
download_file "README.md" "${tmpdir}/README.md"
download_file "LICENSE" "${tmpdir}/LICENSE"
download_file "docs/ALGORITHM.md" "${tmpdir}/docs/ALGORITHM.md"
download_file "docs/PROFILES.md" "${tmpdir}/docs/PROFILES.md"
download_file "docs/WALKTHROUGH.md" "${tmpdir}/docs/WALKTHROUGH.md"
download_file "scripts/install.sh" "${tmpdir}/scripts/install.sh"
download_file "scripts/uninstall.sh" "${tmpdir}/scripts/uninstall.sh"

mkdir -p "$INSTALL_ROOT" "$INSTALL_ROOT/docs" "$INSTALL_ROOT/scripts" "$BIN_DIR"

cp "${tmpdir}/unifiwifioptimizer" "$INSTALL_ROOT/unifiwifioptimizer"
cp "${tmpdir}/profiles.yaml" "$INSTALL_ROOT/profiles.yaml"
cp "${tmpdir}/config.minimal.yaml" "$INSTALL_ROOT/config.minimal.yaml"
cp "${tmpdir}/config.example.yaml" "$INSTALL_ROOT/config.example.yaml"
cp "${tmpdir}/README.md" "$INSTALL_ROOT/README.md"
cp "${tmpdir}/LICENSE" "$INSTALL_ROOT/LICENSE"
cp "${tmpdir}/docs/ALGORITHM.md" "$INSTALL_ROOT/docs/ALGORITHM.md"
cp "${tmpdir}/docs/PROFILES.md" "$INSTALL_ROOT/docs/PROFILES.md"
cp "${tmpdir}/docs/WALKTHROUGH.md" "$INSTALL_ROOT/docs/WALKTHROUGH.md"
cp "${tmpdir}/scripts/install.sh" "$INSTALL_ROOT/scripts/install.sh"
cp "${tmpdir}/scripts/uninstall.sh" "$INSTALL_ROOT/scripts/uninstall.sh"

chmod +x "$INSTALL_ROOT/unifiwifioptimizer" "$INSTALL_ROOT/scripts/install.sh" "$INSTALL_ROOT/scripts/uninstall.sh"

if [ ! -f "$INSTALL_ROOT/config.yaml" ]; then
  cp "$INSTALL_ROOT/config.minimal.yaml" "$INSTALL_ROOT/config.yaml"
fi

cat > "$BIN_DIR/$CMD_NAME" <<EOF
#!/bin/sh
exec "$INSTALL_ROOT/unifiwifioptimizer" "\$@"
EOF

cat > "$BIN_DIR/$UNINSTALL_NAME" <<EOF
#!/bin/sh
exec sh "$INSTALL_ROOT/scripts/uninstall.sh" "\$@"
EOF

chmod +x "$BIN_DIR/$CMD_NAME" "$BIN_DIR/$UNINSTALL_NAME"

run_optional_setup

printf 'Installed %s\n' "$CMD_NAME"
printf '  Files: %s\n' "$INSTALL_ROOT"
printf '  Launcher: %s/%s\n' "$BIN_DIR" "$CMD_NAME"
printf '  Uninstall helper: %s/%s\n' "$BIN_DIR" "$UNINSTALL_NAME"

case ":${PATH:-}:" in
  *:"$BIN_DIR":*) ;;
  *)
    printf '\nAdd this to your shell profile if needed:\n'
    # shellcheck disable=SC2016
    printf '  export PATH="%s:$PATH"\n' "$BIN_DIR"
    ;;
esac
