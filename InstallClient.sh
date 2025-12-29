#!/bin/bash

# Configuration
APP_NAME="mycelium"
INSTALL_DIR="/opt/$APP_NAME"
SYMLINK_PATH="/usr/local/bin/$APP_NAME"


GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' 

echo -e "${GREEN}=== Mycelium VPN Client Installer ===${NC}"

# 1. Check for Root (needed to write to /opt and /usr/local/bin)
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo ./install.sh)${NC}"
  exit 1
fi

# 2. Build the Binaries
echo "Building binaries..."

# Build CLI (The Launcher)

go build -o build/mycelium ./client-cli/main.go 
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to build CLI.${NC}"
    exit 1
fi

# Build Core (The Client)
go build -o build/mycelium-client ./cmd/Client/client.go
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to build Core.${NC}"
    exit 1
fi

# 3. Create Installation Directory
echo "Creating directory $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# 4. Move Binaries
echo "Installing binaries..."
cp build/mycelium "$INSTALL_DIR/"
cp build/mycelium-client "$INSTALL_DIR/"

# 5. Create Symlink (Only for the CLI)
echo "Creating symlink..."
# Remove old symlink if it exists
rm -f "$SYMLINK_PATH"
ln -s "$INSTALL_DIR/$APP_NAME" "$SYMLINK_PATH"

# 6. Set Permissions
chmod +x "$INSTALL_DIR/mycelium"

# === SPECIAL PRIVILEGE SETUP ===
# We set the Core binary to be owned by root and enable the SUID bit.
# This allows the CLI (running as you) to launch the Core (running as root).
chown root:root "$INSTALL_DIR/mycelium-client"
chmod u+s "$INSTALL_DIR/mycelium-client"

echo -e "${GREEN}=== Installation Complete! ===${NC}"
echo "You can now run '$APP_NAME connect' from anywhere."
echo "Binaries location: $INSTALL_DIR"