#!/usr/bin/env bash
echo "=== $(date) ==="
echo "--- OP-TEE advisories ---"
curl -s https://api.github.com/repos/OP-TEE/optee_os/security-advisories | grep -E '"summary"|"published_at"' | head
echo "--- GitHub repos: CDJ-1500X ---"
curl -s "https://api.github.com/search/repositories?q=CDJ-1500X" | grep -E '"full_name"|"description"' | head
echo "--- Manual: https://github.com/search?q=CDJ1500Xv110&type=code"
echo "--- Manual: https://github.com/search?q=4367fd45-4469-42a6-925d-3857b952704a&type=code"
