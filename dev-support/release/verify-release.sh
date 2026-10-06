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
# Checks a release candidate the way a voter would.
#
#   dev-support/release/verify-release.sh <release-candidate-dir>
#
# Verifies every signature and checksum, that the source release carries
# LICENSE and NOTICE, and that its test suite passes. Import the signer's key
# first: curl https://downloads.apache.org/drill/KEYS | gpg --import
# Requires gpg, uv.

set -euo pipefail

dir="$(cd "${1:?usage: $0 <release-candidate-dir>}" && pwd)"
cd "$dir"

for f in *.tar.gz *.whl; do
    gpg --batch --verify "${f}.asc" "$f"
    shasum -a 512 -c "${f}.sha512"
done

src=$(ls apache-drill-mcp-*-src.tar.gz)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar xzf "$src" -C "$work"
root="${work}/${src%.tar.gz}"

for f in LICENSE NOTICE; do
    [[ -f "${root}/${f}" ]] || { echo "${src} is missing ${f}" >&2; exit 1; }
done

uv venv -q "${work}/venv"
VIRTUAL_ENV="${work}/venv" uv pip install -q -e "${root}[dev]"
(cd "$root" && "${work}/venv/bin/pytest" -q -p no:cacheprovider)

echo
echo "All checks passed for ${dir}"
