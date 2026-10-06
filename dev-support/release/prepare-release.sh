#!/usr/bin/env bash
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied.  See the License for the specific
# language governing permissions and limitations under the
# License.
#
# Builds, signs and checksums a release candidate from the current commit.
#
#   dev-support/release/prepare-release.sh <rc-number>
#
# The version comes from pyproject.toml; server.json must agree. Produces in
# dist/release/drill-mcp-<version>-rc<N>/:
#   apache-drill-mcp-<version>-src.tar.gz   the source release voted on
#   drill_mcp-<version>.tar.gz, *.whl       PyPI convenience artifacts
# each with a .asc signature and .sha512 checksum. Requires git, gpg, uv.
#
# Set GPG_KEY to choose a signing key other than gpg's default.

set -euo pipefail

rc="${1:?usage: $0 <rc-number>}"
cd "$(git rev-parse --show-toplevel)"

version=$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')
python3 - "$version" <<'EOF'
import json, sys
v = sys.argv[1]
s = json.load(open("server.json"))
found = {s["version"], *(p["version"] for p in s["packages"])}
if found != {v}:
    sys.exit(f"server.json versions {sorted(found)} do not match pyproject.toml {v}")
EOF

if [[ -n "$(git status --porcelain)" ]]; then
    echo "working tree is not clean; commit or stash first" >&2
    exit 1
fi

tag="v${version}-rc${rc}"
if [[ "$(git rev-parse HEAD)" != "$(git rev-parse -q --verify "${tag}^{commit}" || true)" ]]; then
    echo "HEAD is not tagged ${tag}; run: git tag -s ${tag} -m 'drill-mcp ${version} RC${rc}'" >&2
    exit 1
fi

out="dist/release/drill-mcp-${version}-rc${rc}"
rm -rf "$out"
mkdir -p "$out"

# Commit time as the build timestamp, so anyone can rebuild the same bytes.
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)

src="apache-drill-mcp-${version}-src"
git archive --format=tar.gz --prefix="${src}/" -o "${out}/${src}.tar.gz" HEAD
uv build --sdist --wheel -o "$out" .
rm -f "${out}/.gitignore"  # uv drops one into its output directory
uvx twine check "$out"/drill_mcp-*

cd "$out"
for f in *.tar.gz *.whl; do
    gpg --batch --yes --armor --detach-sign ${GPG_KEY:+--local-user "$GPG_KEY"} "$f"
    shasum -a 512 "$f" > "${f}.sha512"
done

cat <<EOF

Release candidate ready in ${out}:
$(ls -1)

Next steps:
  1. git push origin ${tag}
  2. svn co https://dist.apache.org/repos/dist/dev/drill/ drill-dist-dev
     copy ${out} into it as drill-mcp-${version}-rc${rc}/, then svn add and commit
  3. Run dev-support/release/verify-release.sh on the staged copy
  4. Call the vote on dev@drill.apache.org (72 hours, 3 binding +1s)
EOF
