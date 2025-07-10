#!/bin/bash

# MCP Security Jekyll Cleanup Script
# This script removes all files and directories created by setup.sh

set -e

echo "🧹 MCP Security Jekyll Cleanup"
echo "==============================="

# Check if we're in the right directory
if [ ! -f "index.md" ]; then
    echo "❌ Error: Please run this script from the docs directory"
    echo "   Expected location: /Users/kurt/GitHub/MCP-Security/modelcontextprotocol-security.io/docs/"
    exit 1
fi

# Show what will be removed
echo "📋 The following will be removed:"
echo "=================================="

# Check what exists and show it
items_to_remove=()

if [ -d "_site" ]; then
    echo "✓ _site/ (Jekyll build output)"
    items_to_remove+=("_site")
fi

if [ -d ".jekyll-cache" ]; then
    echo "✓ .jekyll-cache/ (Jekyll cache)"
    items_to_remove+=(".jekyll-cache")
fi

if [ -d ".bundle" ]; then
    echo "✓ .bundle/ (Bundler configuration)"
    items_to_remove+=(".bundle")
fi

if [ -d "vendor" ]; then
    echo "✓ vendor/ (Bundler gems)"
    items_to_remove+=("vendor")
fi

if [ -f "Gemfile.lock" ]; then
    echo "✓ Gemfile.lock (Bundler lock file)"
    items_to_remove+=("Gemfile.lock")
fi

if [ -f ".jekyll-metadata" ]; then
    echo "✓ .jekyll-metadata (Jekyll metadata)"
    items_to_remove+=(".jekyll-metadata")
fi

if [ -f "assets/images/mcp-security-logo.svg" ]; then
    echo "✓ assets/images/mcp-security-logo.svg (generated logo)"
    items_to_remove+=("assets/images/mcp-security-logo.svg")
fi

if [ -f ".gitignore" ]; then
    echo "? .gitignore (may contain manual changes - will ask)"
    items_to_remove+=(".gitignore")
fi

# If nothing to remove, exit
if [ ${#items_to_remove[@]} -eq 0 ]; then
    echo ""
    echo "✅ Nothing to clean up! Directory is already clean."
    exit 0
fi

echo ""
echo "⚠️  WARNING: This will permanently delete the above files and directories."
echo "   Make sure you have committed any important changes to Git first."
echo ""

# Ask for confirmation
read -p "🤔 Do you want to proceed with cleanup? (y/N): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Cleanup cancelled."
    exit 1
fi

echo ""
echo "🧹 Starting cleanup..."
echo "====================="

# Remove items
for item in "${items_to_remove[@]}"; do
    if [ "$item" = ".gitignore" ]; then
        echo "🤔 .gitignore found. This file may contain manual changes."
        read -p "   Remove .gitignore? (y/N): " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -f ".gitignore"
            echo "✅ Removed .gitignore"
        else
            echo "⏭️  Skipped .gitignore"
        fi
    elif [ -d "$item" ]; then
        rm -rf "$item"
        echo "✅ Removed directory: $item"
    elif [ -f "$item" ]; then
        rm -f "$item"
        echo "✅ Removed file: $item"
    fi
done

# Clean up empty directories
echo ""
echo "🔍 Cleaning up empty directories..."
if [ -d "assets/images" ] && [ -z "$(ls -A assets/images)" ]; then
    rmdir assets/images
    echo "✅ Removed empty directory: assets/images"
fi

if [ -d "assets" ] && [ -z "$(ls -A assets)" ]; then
    rmdir assets
    echo "✅ Removed empty directory: assets"
fi

# Final status
echo ""
echo "✅ Cleanup complete!"
echo ""
echo "📝 What was cleaned up:"
echo "   - All Jekyll build artifacts"
echo "   - All bundler-generated files"
echo "   - All cache directories"
echo "   - Generated placeholder files"
echo ""
echo "🔄 To set up again, run:"
echo "   ./setup.sh"
echo ""
echo "💡 Note: Your source files (*.md, _config.yml, etc.) were not touched."
