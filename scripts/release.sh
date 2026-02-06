#!/usr/bin/env bash
set -euo pipefail

# Get the latest tag, default to v0.0.0 if none exists
latest=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
echo "Current version: $latest"

# Parse the version
version=${latest#v}
IFS='.' read -r major minor patch <<< "$version"

# Bump patch version
new_patch=$((patch + 1))
new_version="v${major}.${minor}.${new_patch}"
echo "New version: $new_version"

# Create and push the tag
git tag -a "$new_version" -m "Release $new_version"
git push origin "$new_version"

echo "Released $new_version"
