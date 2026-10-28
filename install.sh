#!/usr/bin/env bash
# ==============================================================================
# VIBE CODER WEB SECURITY PROTOCOL INSTALLER
# One-line installer to inject 9-layer web security rules into any project.
# ==============================================================================

set -e

# Terminal colors
BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
echo "=========================================================="
echo "    🛡️  VIBE CODER WEB SECURITY PROTOCOL INJECTOR 🛡️     "
echo "  Hardening AI-generated code across 9 critical layers   "
echo "=========================================================="
echo -e "${NC}"

TARGET_DIR="$(pwd)"
echo -e "${BLUE}[*] Target Project Directory:${NC} ${TARGET_DIR}"

BASE_URL="https://raw.githubusercontent.com/recode-project/vibe-security-protocol/main"

# Function to download or copy file
install_file() {
    local filename="$1"
    local dest="${TARGET_DIR}/${filename}"

    # Create destination directory if needed
    mkdir -p "$(dirname "$dest")"

    # Check if local source exists (if running from cloned repo)
    if [ -f "$filename" ]; then
        cp "$filename" "$dest"
        echo -e "${GREEN}[+] Installed:${NC} ${filename} (from local)"
    else
        # Download from GitHub repository
        if command -v curl >/dev/null 2>&1; then
            curl -sSL "${BASE_URL}/${filename}" -o "$dest"
            echo -e "${GREEN}[+] Downloaded & Installed:${NC} ${filename}"
        elif command -v wget >/dev/null 2>&1; then
            wget -q "${BASE_URL}/${filename}" -O "$dest"
            echo -e "${GREEN}[+] Downloaded & Installed:${NC} ${filename}"
        else
            echo -e "${YELLOW}[!] Warning:${NC} Neither curl nor wget found. Cannot download ${filename}."
        fi
    fi
}

echo -e "\n${BOLD}Installing Universal Web Security Rule Pack...${NC}"

# Core Security Standard Document
install_file "WEB_SECURITY_PROTOCOL.md"

# AI Agent Specific Rule Files
install_file ".cursorrules"
install_file "CLAUDE.md"
install_file ".windsurfrules"
install_file "AGENTS.md"
install_file ".github/copilot-instructions.md"

echo -e "\n${GREEN}${BOLD}✓ Installation Complete!${NC}"
echo -e "=========================================================="
echo -e "${BOLD}${YELLOW}👉 NEXT STEP FOR VIBE CODERS:${NC}"
echo -e "Open your AI coding tool (Cursor / Claude Code / Windsurf / Copilot / Cline) and send this prompt:\n"
echo -e "${CYAN}${BOLD}\"Audit this entire codebase and apply the 9 Hardening Layers from WEB_SECURITY_PROTOCOL.md. Fix all SQL injection risks, secure CORS and cookies, add rate limiting, block sensitive file access, and eliminate hardcoded secrets.\"${NC}\n"
echo -e "=========================================================="
