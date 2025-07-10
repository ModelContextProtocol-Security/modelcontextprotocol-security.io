#!/bin/bash

# MCP Security Jekyll - Make Scripts Executable
# This script makes the setup and serve scripts executable

echo "🔧 Making scripts executable..."

# Make scripts executable
chmod +x setup.sh
chmod +x serve.sh

echo "✅ Scripts are now executable!"
echo ""
echo "Usage:"
echo "  ./setup.sh          - Set up Jekyll environment"
echo "  ./setup.sh --install-deps - Set up with dependency installation"
echo "  ./serve.sh           - Start development server"
echo ""
echo "Next steps:"
echo "1. Run ./setup.sh to initialize Jekyll"
echo "2. Run ./serve.sh to start the development server"
echo "3. Visit http://localhost:4000 to see your site"
