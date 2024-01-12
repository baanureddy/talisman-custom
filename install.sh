#!/bin/bash
set -euo pipefail

declare TALISMAN_BINARY_NAME

E_UNSUPPORTED_ARCH=5
DEBUG=${DEBUG:-''}
VERSION=${VERSION:-'latest'}
INSTALL_ORG_REPO=${INSTALL_ORG_REPO:-'thoughtworks/talisman'}
INSTALL_LOCATION=${INSTALL_LOCATION:-'/usr/local/bin'}

function echo_error() {
  echo -ne "$(tput setaf 1)" >&2
  echo "$1" >&2
  echo -ne "$(tput sgr0)" >&2
}

function echo_debug() {
  [[ -z "$DEBUG" ]] && return
  echo -ne "$(tput setaf 3)" >&2
  echo "$1" >&2
  echo -ne "$(tput sgr0)" >&2
}

function echo_success() {
  echo -ne "$(tput setaf 2)"
  echo "$1" >&2
  echo -ne "$(tput sgr0)"
}

function operating_system() {
  OS=$(uname -s)
  case $OS in
  "Linux")
    echo "linux"
    ;;
  "Darwin")
    echo "darwin"
    ;;
  MINGW32_NT-* | MINGW64_NT-* | MSYS_NT-*)
    echo "windows"
    ;;
  *)
    echo_error "Talisman currently only supports Windows, Linux, and MacOS (darwin) systems."
    echo_error "If this is a problem for you, please open an issue: https://github.com/$INSTALL_ORG_REPO/issues/new"
    exit $E_UNSUPPORTED_ARCH
    ;;
  esac
}

function architecture() {
  ARCH=$(uname -m)
  case $ARCH in
  "x86_64")
    echo "amd64"
    ;;
  "i686" | "i386")
    echo "386"
    ;;
  "arm64" | "aarch64")
    echo "arm64"
    ;;
  *)
    echo_error "Talisman currently only supports x86 and x86_64 and arm64 architectures."
    echo_error "If this is a problem for you, please open an issue: https://github.com/$INSTALL_ORG_REPO/issues/new"
    exit $E_UNSUPPORTED_ARCH
    ;;
  esac
}

function set_talisman_binary_name() {
  TALISMAN_BINARY_NAME="talisman_$(operating_system)_$(architecture)"
  if [ "$(operating_system)" = "windows" ]; then
    TALISMAN_BINARY_NAME="$TALISMAN_BINARY_NAME.exe"
  fi
}

function download() {
  OBJECT=$1
  DOWNLOAD_URL=$(curl -Ls https://api.github.com/repos/"$INSTALL_ORG_REPO"/releases/latest |
     grep download_url | awk '{print $2}' | tr -d '"' | grep "$OBJECT")

  echo_debug "Downloading $OBJECT from $DOWNLOAD_URL"
  curl --location --silent "$DOWNLOAD_URL" >"$TEMP_DIR/$OBJECT"
}

function verify_checksum() {
  FILE_NAME=$1
  CHECKSUM_FILE_NAME='checksums'
  echo_debug "Verifying checksum for $FILE_NAME"
  download $CHECKSUM_FILE_NAME

  pushd "$TEMP_DIR" >/dev/null 2>&1

  if ! command -v shasum &> /dev/null; then
    sha256sum --ignore-missing -c $CHECKSUM_FILE_NAME
  else
    shasum -a 256 --ignore-missing -c $CHECKSUM_FILE_NAME
  fi
  popd >/dev/null 2>&1
  echo_debug "Checksum verification successfully!"
  echo
}

function download_talisman_binary() {
  download "$TALISMAN_BINARY_NAME"
  verify_checksum "$TALISMAN_BINARY_NAME"
}

function install_talisman() {
  if (touch "$INSTALL_LOCATION/$TALISMAN_BINARY_NAME" &>/dev/null); then
    cp "$TEMP_DIR/$TALISMAN_BINARY_NAME" "$INSTALL_LOCATION/$TALISMAN_BINARY_NAME"
    chmod +x "$INSTALL_LOCATION/$TALISMAN_BINARY_NAME"
    ln -s "$INSTALL_LOCATION/$TALISMAN_BINARY_NAME" "$INSTALL_LOCATION/talisman"
  elif (which sudo &>/dev/null); then
    sudo cp "$TEMP_DIR/$TALISMAN_BINARY_NAME" "$INSTALL_LOCATION/$TALISMAN_BINARY_NAME"
    sudo chmod +x "$INSTALL_LOCATION/$TALISMAN_BINARY_NAME"
    sudo ln -s "$INSTALL_LOCATION/$TALISMAN_BINARY_NAME" "$INSTALL_LOCATION/talisman"
  else
    echo_error "Insufficient permission to install to $INSTALL_LOCATION"
    exit 126
  fi
}

function run() {
  TEMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'talisman_setup')
  # shellcheck disable=SC2064
  trap "rm -r $TEMP_DIR" EXIT
  chmod 0700 "$TEMP_DIR"

  if [ ! -d "$INSTALL_LOCATION" ]; then
    echo_error "$INSTALL_LOCATION is not a directory!"
    exit 1
  fi

  set_talisman_binary_name
  echo_success "Downloading talisman binary"
  download_talisman_binary
  install_talisman
}

run
