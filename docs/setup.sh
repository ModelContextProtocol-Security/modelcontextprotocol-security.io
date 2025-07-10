#!/bin/bash

# MCP Security Jekyll Setup Script
# This script sets up Jekyll with Just the Docs theme for the MCP Security project

set -e

echo "🚀 Setting up MCP Security Jekyll Site"
echo "======================================"

# Check if we're in the right directory
if [ ! -f "index.md" ]; then
    echo "❌ Error: Please run this script from the docs directory"
    echo "   Expected location: /Users/kurt/GitHub/MCP-Security/modelcontextprotocol-security.io/docs/"
    exit 1
fi

# Check if Ruby is installed
if ! command -v ruby &> /dev/null; then
    echo "❌ Ruby is not installed. Please install Ruby first:"
    echo "   For macOS: brew install ruby"
    echo "   For Ubuntu: sudo apt-get install ruby-full"
    exit 1
fi

# Check if Bundler is installed
if ! command -v bundle &> /dev/null; then
    echo "📦 Installing Bundler..."
    gem install bundler
fi

# Install Jekyll dependencies
echo "📦 Installing Jekyll dependencies..."
bundle install

# Create necessary directories if they don't exist
echo "📁 Creating directory structure..."
mkdir -p _site
mkdir -p .jekyll-cache

# Create a simple placeholder logo
echo "🎨 Creating placeholder logo..."
mkdir -p assets/images
cat > assets/images/mcp-security-logo.svg << 'EOF'
<svg width="100" height="100" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
  <rect width="100" height="100" fill="#1f4e79"/>
  <circle cx="50" cy="50" r="30" fill="#0066cc"/>
  <text x="50" y="55" text-anchor="middle" fill="white" font-family="Arial, sans-serif" font-size="12" font-weight="bold">MCP</text>
</svg>
EOF

# Create .gitignore if it doesn't exist
if [ ! -f ".gitignore" ]; then
    echo "📝 Creating .gitignore..."
    cat > .gitignore << 'EOF'
_site/
.sass-cache/
.jekyll-cache/
.jekyll-metadata
.bundle/
vendor/
Gemfile.lock
.DS_Store
EOF
fi

# Test the Jekyll build
echo "🔧 Testing Jekyll build..."
bundle exec jekyll build --verbose

# Success message
echo ""
echo "✅ Setup complete! Your Jekyll site is ready."
echo ""
echo "Next steps:"
echo "1. Start the development server:"
echo "   bundle exec jekyll serve"
echo ""
echo "2. Visit your site at: http://localhost:4000"
echo ""
echo "3. When ready to deploy, commit and push to GitHub:"
echo "   git add ."
echo "   git commit -m 'Add Jekyll theme with CSA styling'"
echo "   git push origin main"
echo ""
echo "4. GitHub Pages will automatically build and deploy your site!"
echo ""
echo "📚 Documentation:"
echo "   - Just the Docs theme: https://just-the-docs.github.io/just-the-docs/"
echo "   - Jekyll documentation: https://jekyllrb.com/docs/"
echo "   - GitHub Pages: https://pages.github.com/"
