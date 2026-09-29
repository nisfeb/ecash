#!/usr/bin/env bash

# Build the ecash desks and (optionally) copy them into a mounted desk.
#
#   ./build.sh                          build the desks into dist/ and dist-tessera/
#   ./build.sh -p <pier>/ecash          build, then deploy the %ecash mint desk
#   ./build.sh tessera -p <pier>/tessera   build, then deploy %tessera
#   ./build.sh clean                    remove the dist dirs
#
# Requires peru (https://github.com/buildinspace/peru) to pull the shared
# base-dev dependencies (default-agent, dbug, the standard marks).
set -euo pipefail

COPY_PATH=""
COMMAND=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -p)
      if [[ -z "${2:-}" ]]; then
        echo "Error: -p flag requires a filepath argument" >&2
        exit 1
      fi
      COPY_PATH="$2"
      shift 2
      ;;
    *)
      if [[ -n "$COMMAND" ]]; then
        echo "Error: only one command is allowed" >&2
        exit 1
      fi
      COMMAND="$1"
      shift
      ;;
  esac
done

if [[ -z "$COMMAND" ]]; then
  COMMAND="build"
fi

check_peru_installed() {
  if ! command -v peru &> /dev/null; then
    echo "Error: peru is not installed or not in PATH." >&2
    echo "See: https://github.com/buildinspace/peru" >&2
    exit 1
  fi
}

# Build the desks: dist/ = %ecash (value mint), dist-tessera/ = %tessera
# (access tokens). peru.yaml imports the shared base-dev files into each.
sync_deps() {
  check_peru_installed

  if [[ ! -d desk ]]; then
    echo "Error: desk directory not found." >&2
    exit 1
  fi

  # Regenerate the shared libs for the other desks (single source of truth
  # is desk/lib; these copies are gitignored).
  make -s sync-libs

  echo "Preparing dist/ and dist-tessera/..."
  rm -rf dist dist-tessera
  mkdir -p dist dist-tessera

  # Pull base-dev deps FIRST, into the empty dirs, so peru only ever manages its
  # own files — otherwise a mark we also ship (mar/txt) looks "modified" to peru
  # on the second run and it aborts.
  echo "Running peru sync..."
  if ! peru sync 2>&1; then
    echo "Error: peru sync failed. Cleaning up..." >&2
    rm -rf dist dist-tessera
    exit 1
  fi

  # ...then overlay our desk files on top (ours win for any shared mark).
  echo "Overlaying desk files..."
  cp -r desk/* dist/
  cp -r desk-tessera/* dist-tessera/
}

copy_to_path() {
  local target_path="$1"
  local dist_dir="${2:-dist}"

  if [[ ! -d "$dist_dir" ]]; then
    echo "Error: $dist_dir not found. Run build first." >&2
    exit 1
  fi

  if [[ ! -d "$target_path" ]]; then
    echo "Error: target path '$target_path' does not exist (mount the desk first)." >&2
    exit 1
  fi

  # -p wipes the target, so it must be a mounted desk (a pier, a home dir
  # or a typo would be emptied): every desk carries sys.kelvin
  if [[ ! -f "$target_path/sys.kelvin" ]]; then
    echo "Error: '$target_path' has no sys.kelvin; is it a mounted desk?" >&2
    exit 1
  fi

  echo "Cleaning desk at $target_path..."
  rm -rf "$target_path"/*

  echo "Copying $dist_dir to $target_path..."
  cp -r "$dist_dir"/* "$target_path"/

  echo "Copy completed successfully."
}

build() {
  sync_deps
  echo "Build completed (dist/ = %ecash, dist-tessera/ = %tessera)."
  if [[ -n "$COPY_PATH" ]]; then
    copy_to_path "$COPY_PATH" dist
  fi
}

build_tessera() {
  sync_deps
  echo "Build completed (dist-tessera/ = %tessera)."
  if [[ -n "$COPY_PATH" ]]; then
    copy_to_path "$COPY_PATH" dist-tessera
  fi
}

clean() {
  echo "Removing the dist directories..."
  rm -rf dist dist-tessera
}

case "$COMMAND" in
  build)
    build
    ;;
  tessera)
    build_tessera
    ;;
  clean)
    clean
    ;;
  help)
    echo "Usage: $0 [-p path] [build|tessera|clean|help]"
    echo
    echo "  build      : build the desks (dist/ = %ecash, dist-tessera/ = %tessera)"
    echo "  tessera    : same build; with -p, deploy the %tessera desk"
    echo "  clean      : remove the dist directories"
    echo
    echo "Options:"
    echo "  -p path    : after building, copy the desk into the mounted desk at this path"
    echo "               (removes existing contents of that desk first)"
    echo "                 build    + -p  ->  copies dist/ (%ecash)"
    echo "                 tessera  + -p  ->  copies dist-tessera/ (%tessera)"
    echo
    echo "  If no command is given, build is the default."
    echo "  peru must be installed: https://github.com/buildinspace/peru"
    ;;
  *)
    echo "Error: unknown command '$COMMAND'" >&2
    exit 1
    ;;
esac
