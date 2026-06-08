#!/usr/bin/env bash

# Build the ecash desks and (optionally) copy them into a mounted desk.
#
#   ./build.sh                          build both desks into dist/ and dist-services/
#   ./build.sh -p <pier>/ecash          build, then deploy the %ecash mint desk
#   ./build.sh services -p <pier>/ecash-services   build, then deploy %ecash-services
#   ./build.sh clean                    remove dist/ and dist-services/
#
# Requires peru (https://github.com/buildinspace/peru) to pull the shared
# base-dev dependencies (default-agent, dbug, the standard marks).

COPY_PATH=""
COMMAND=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -p)
      if [[ -z "$2" ]]; then
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

# Build both desks: dist/ = %ecash (value mint), dist-services/ = %ecash-services
# (access layer). peru.yaml imports the shared base-dev files into both.
sync_deps() {
  check_peru_installed

  if [[ ! -d desk ]]; then
    echo "Error: desk directory not found." >&2
    exit 1
  fi

  # Regenerate the shared crypto for the services desk (single source of truth
  # is desk/lib; these copies are gitignored).
  mkdir -p desk-services/lib
  cp desk/lib/curve.hoon desk/lib/bdhke.hoon desk-services/lib/

  echo "Preparing dist/ and dist-services/..."
  rm -rf dist dist-services
  mkdir -p dist dist-services

  # Pull base-dev deps FIRST, into the empty dirs, so peru only ever manages its
  # own files — otherwise a mark we also ship (mar/txt) looks "modified" to peru
  # on the second run and it aborts.
  echo "Running peru sync..."
  if ! peru sync 2>&1; then
    echo "Error: peru sync failed. Cleaning up..." >&2
    rm -rf dist dist-services
    exit 1
  fi

  # ...then overlay our desk files on top (ours win for any shared mark).
  echo "Overlaying desk files..."
  cp -r desk/* dist/
  if [[ -d desk-services ]]; then
    cp -r desk-services/* dist-services/
  fi
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

  echo "Cleaning desk at $target_path..."
  rm -rf "$target_path"/*

  echo "Copying $dist_dir to $target_path..."
  cp -r "$dist_dir"/* "$target_path"/

  echo "Copy completed successfully."
}

build() {
  sync_deps
  echo "Build completed (dist/ = %ecash, dist-services/ = %ecash-services)."
  if [[ -n "$COPY_PATH" ]]; then
    copy_to_path "$COPY_PATH" dist
  fi
}

build_services() {
  sync_deps
  echo "Build completed (dist-services/ = %ecash-services)."
  if [[ -n "$COPY_PATH" ]]; then
    copy_to_path "$COPY_PATH" dist-services
  fi
}

clean() {
  if [[ -d dist ]]; then
    echo "Removing dist directory..."
    rm -rf dist
  fi
  if [[ -d dist-services ]]; then
    echo "Removing dist-services directory..."
    rm -rf dist-services
  fi
}

case "$COMMAND" in
  build)
    build
    ;;
  services)
    build_services
    ;;
  clean)
    clean
    ;;
  help)
    echo "Usage: $0 [-p path] [build|services|clean|help]"
    echo
    echo "  build      : build both desks (dist/ = %ecash, dist-services/ = %ecash-services)"
    echo "  services   : same build; with -p, deploy the %ecash-services desk"
    echo "  clean      : remove dist/ and dist-services/"
    echo
    echo "Options:"
    echo "  -p path    : after building, copy the desk into the mounted desk at this path"
    echo "               (removes existing contents of that desk first)"
    echo "                 build    + -p  ->  copies dist/ (%ecash)"
    echo "                 services + -p  ->  copies dist-services/ (%ecash-services)"
    echo
    echo "  If no command is given, build is the default."
    echo "  peru must be installed: https://github.com/buildinspace/peru"
    ;;
  *)
    echo "Error: unknown command '$COMMAND'" >&2
    exit 1
    ;;
esac
