#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "[ERROR] Installation failed at line $LINENO. Inspect /var/log/nccl-setup/install.log" >&2' ERR

# ============================================================
# NCCL LAB INSTALLER
# OS: Ubuntu 22.04 LTS, x86-64
# Driver: NVIDIA 570 series
# Python: 3.10
# PyTorch: 2.7.1 + CUDA 12.8 wheels
# ============================================================

DRIVER_PACKAGE="nvidia-driver-570"
TORCH_VERSION="2.7.1"
TORCHVISION_VERSION="0.22.1"
TORCHAUDIO_VERSION="2.7.1"
VENV="/opt/nccl-venv"
LOGDIR="/var/log/nccl-setup"
TORCH_INDEX="https://download.pytorch.org/whl/cu128"

log() { echo -e "\n[INFO] $*"; }
die() { echo -e "\n[ERROR] $*" >&2; exit 1; }

# -------------------- Preflight -----------------------------

[[ $EUID -eq 0 ]] || die "Run: sudo bash install_nccl_stack.sh"
[[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]] ||
    die "Run from your normal user account using sudo."

TARGET_USER="$SUDO_USER"
TARGET_GROUP="$(id -gn "$TARGET_USER")"

source /etc/os-release

[[ "$ID" == "ubuntu" && "$VERSION_ID" == "22.04" ]] ||
    die "This script requires Ubuntu 22.04 LTS."

[[ "$(dpkg --print-architecture)" == "amd64" ]] ||
    die "Only x86-64 / amd64 is supported."

command -v lspci >/dev/null 2>&1 ||
    die "lspci is unavailable. Install pciutils first."

lspci | grep -qi NVIDIA ||
    die "No NVIDIA GPU detected. No driver changes have been made."

FREE_GB="$(df -BG /opt | awk 'NR==2 {gsub(/G/,"",$4); print $4}')"
[[ "$FREE_GB" =~ ^[0-9]+$ ]] ||
    die "Unable to determine free disk space."

(( FREE_GB >= 15 )) ||
    die "At least 15 GB free on the /opt filesystem is required."

[[ ! -e "$VENV" ]] ||
    die "$VENV already exists. Inspect it before rerunning."

mkdir -p "$LOGDIR"
exec > >(tee -a "$LOGDIR/install.log") 2>&1

log "Recording existing system state"
{
    date
    cat /etc/os-release
    uname -a
    lspci | grep -i NVIDIA || true
    nvidia-smi || true
    dpkg -l | grep -E 'nvidia|cuda|python3' || true
} > "$LOGDIR/pre-install.txt"

# -------------------- System packages ----------------------

log "Updating APT metadata and installing prerequisites"
export DEBIAN_FRONTEND=noninteractive

apt-get update

apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    build-essential \
    git \
    pciutils \
    iproute2 \
    ethtool \
    netcat-openbsd \
    linux-headers-generic \
    python3.10 \
    python3.10-venv \
    python3.10-dev \
    bpftrace \
    bpfcc-tools

# -------------------- NVIDIA driver ------------------------

log "Checking fixed NVIDIA driver package: $DRIVER_PACKAGE"

if ! apt-cache show "$DRIVER_PACKAGE" >/dev/null 2>&1; then
    die "$DRIVER_PACKAGE is unavailable in configured APT repositories.
Enable a compatible Ubuntu NVIDIA driver repository and rerun.
No alternative driver series will be selected automatically."
fi

log "Installing NVIDIA driver 570 series"
apt-get install -y "$DRIVER_PACKAGE"

log "Installed NVIDIA driver package version:"
dpkg-query -W -f='${Package} ${Version}\n' "$DRIVER_PACKAGE"

# -------------------- Python environment --------------------

log "Creating isolated Python 3.10 environment"

python3.10 --version
python3.10 -m venv "$VENV"

chown -R "$TARGET_USER:$TARGET_GROUP" "$VENV"

log "Installing pinned packaging tools"
runuser -u "$TARGET_USER" -- \
    "$VENV/bin/python" -m pip install \
    "pip==25.1.1" \
    "setuptools==80.9.0" \
    "wheel==0.45.1"

# -------------------- PyTorch + CUDA runtime ---------------

log "Installing pinned PyTorch CUDA 12.8 wheels"

runuser -u "$TARGET_USER" -- \
    "$VENV/bin/python" -m pip install \
    "torch==$TORCH_VERSION" \
    "torchvision==$TORCHVISION_VERSION" \
    "torchaudio==$TORCHAUDIO_VERSION" \
    --index-url "$TORCH_INDEX"

runuser -u "$TARGET_USER" -- \
    "$VENV/bin/python" -m pip install \
    "numpy==1.26.4"

# -------------------- Verification -------------------------

log "Checking Python package consistency"

runuser -u "$TARGET_USER" -- \
    "$VENV/bin/python" -m pip check

log "Verifying pinned Python and CUDA build"

runuser -u "$TARGET_USER" -- "$VENV/bin/python" - <<'PY'
import sys
import torch
import torchvision
import torchaudio

assert sys.version_info[:2] == (3, 10), sys.version
assert torch.__version__.split("+")[0] == "2.7.1", torch.__version__
assert torchvision.__version__.split("+")[0] == "0.22.1"
assert torchaudio.__version__.split("+")[0] == "2.7.1"
assert torch.version.cuda == "12.8", torch.version.cuda

print("Python:", sys.version.split()[0])
print("PyTorch:", torch.__version__)
print("torchvision:", torchvision.__version__)
print("torchaudio:", torchaudio.__version__)
print("PyTorch CUDA runtime:", torch.version.cuda)
print("CUDA available:", torch.cuda.is_available())

if torch.cuda.is_available():
    print("GPU:", torch.cuda.get_device_name(0))
    print("GPU capability:", torch.cuda.get_device_capability(0))
    print("NCCL:", torch.cuda.nccl.version())
else:
    print("GPU is not available in this session.")
    print("Reboot if required, then rerun GPU verification.")
PY

log "Saving Python package inventory"

"$VENV/bin/python" -m pip freeze \
    > "$LOGDIR/requirements-lock.txt"

chown "$TARGET_USER:$TARGET_GROUP" \
    "$LOGDIR/requirements-lock.txt"

# -------------------- Reboot decision ----------------------

echo
echo "============================================================"
echo "Installation stage completed."
echo "Driver package: $DRIVER_PACKAGE"
echo "Python environment: $VENV"
echo "Install log: $LOGDIR/install.log"
echo "Package inventory: $LOGDIR/requirements-lock.txt"
echo "============================================================"
echo

read -r -p "Reboot now to activate the driver if required? [y/N] " answer

if [[ "$answer" =~ ^[Yy]$ ]]; then
    log "Rebooting system"
    systemctl reboot
else
    echo "Reboot manually when ready: sudo reboot"
fi
