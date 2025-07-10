#!/bin/bash

# MCP Security Jekyll - Make All Scripts Executable
# This script makes all the bash scripts executable

echo "🔧 Making all scripts executable..."

# Make all scripts executable
chmod +x setup.sh
chmod +x serve.sh
chmod +x make-executable.sh
chmod +x deploy-navigation-fix.sh

echo "✅ All scripts are now executable!"
echo ""
echo "Available scripts:"
echo "  ./setup.sh                  - Set up Jekyll environment"
echo "  ./serve.sh                  - Start development server"
echo "  ./deploy-navigation-fix.sh  - Deploy navigation fixes to GitHub Pages"
echo "  ./make-executable.sh        - Make scripts executable (this script)"
echo ""
echo "🚀 To fix the navigation issue on your live site:"
echo "   ./deploy-navigation-fix.sh"
