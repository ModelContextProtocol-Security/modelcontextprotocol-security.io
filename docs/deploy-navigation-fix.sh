#!/bin/bash

# MCP Security Jekyll - Deploy Navigation Fix
# This script helps deploy the navigation fixes to GitHub Pages

echo "🚀 Deploying Navigation Fix to GitHub Pages"
echo "==========================================="

# Check if we're in the right directory
if [ ! -f "index.md" ]; then
    echo "❌ Error: Please run this script from the docs directory"
    echo "   Expected location: /Users/kurt/GitHub/MCP-Security/modelcontextprotocol-security.io/docs/"
    exit 1
fi

# Show what we're about to commit
echo "📋 Files to be committed:"
echo "========================"
git status --porcelain

echo ""
echo "📝 Changes made:"
echo "=================="
echo "✅ Updated home.html layout to use 'default' layout (preserves navigation)"
echo "✅ Updated working group references to 'Model Context Protocol Security Working Group'"
echo "✅ Added proper frontmatter to all major sections:"
echo "   - Hardening Guide (nav_order: 2)"
echo "   - Operations Guide (nav_order: 3)"
echo "   - Reference Patterns (nav_order: 4)"
echo "   - Audit Tools (nav_order: 5)"
echo "   - Tools & Scripts (nav_order: 6)"
echo "   - Vulnerability Database (nav_order: 7)"
echo "   - Community (nav_order: 8)"
echo "   - Blog (nav_order: 9)"
echo "   - Events (nav_order: 10)"
echo "   - Security Advisories (nav_order: 11)"
echo ""

# Ask for confirmation
read -p "🤔 Do you want to commit and push these changes? (y/N): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "📦 Committing changes..."
    git add .
    git commit -m "Fix navigation and update working group references

- Updated home.html layout to inherit from default layout
- Added navigation frontmatter to all major sections
- Configured proper nav_order for hierarchical navigation
- Added has_children property for parent sections
- Updated references from 'Blockchain Working Group' to 'Model Context Protocol Security Working Group'
- This should restore the Just the Docs navigation sidebar"

    echo "🚀 Pushing to GitHub..."
    git push origin main

    echo ""
    echo "✅ Changes pushed successfully!"
    echo ""
    echo "📍 Your site will be updated in 1-3 minutes at:"
    echo "   https://modelcontextprotocol-security.io/"
    echo ""
    echo "🔍 Expected changes:"
    echo "   - Navigation sidebar should now appear on the left"
    echo "   - All major sections should be visible in navigation"
    echo "   - Navigation should be hierarchical with proper ordering"
    echo "   - Hero section should still appear on homepage"
    echo ""
    echo "🎯 If navigation still doesn't appear, check:"
    echo "   - GitHub Pages build status in repository Actions tab"
    echo "   - Browser cache (try hard refresh: Ctrl+F5)"
    echo "   - Console errors in browser developer tools"
    echo ""
else
    echo "❌ Deployment cancelled. Changes not committed."
    echo ""
    echo "💡 To deploy later, run:"
    echo "   git add ."
    echo "   git commit -m 'Fix navigation'"
    echo "   git push origin main"
fi

echo ""
echo "🎉 Done!"
