#!/usr/bin/env bash

# MCP Security Jekyll Development Server Script
# This script starts the Jekyll development server with live reload

set -e

echo "🚀 Starting MCP Security Jekyll Development Server"
echo "================================================="

# Check if we're in the right directory
if [ ! -f "index.md" ]; then
    echo "❌ Error: Please run this script from the docs directory"
    echo "   Expected location: /Users/kurt/GitHub/MCP-Security/modelcontextprotocol-security.io/docs/"
    exit 1
fi

# Check if dependencies are installed
if [ ! -f "Gemfile.lock" ]; then
    echo "📦 Installing dependencies first..."
    bundle install
fi

# Start the Jekyll server
echo "🌐 Starting Jekyll server..."
echo "   Site will be available at: http://localhost:4000"
echo "   Press Ctrl+C to stop the server"
echo ""

# Start Jekyll with live reload, drafts, and future posts
bundle exec jekyll serve --host 0.0.0.0 --port 4000 --livereload --drafts --future --incremental

echo ""
echo "👋 Jekyll server stopped"
