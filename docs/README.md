# MCP Security Jekyll Website

A professional Jekyll website for the Model Context Protocol Security project, styled to match Cloud Security Alliance branding.

## 🚀 Quick Start

### Prerequisites

- **Ruby** (2.7 or higher)
- **Bundler** (Ruby gem manager)
- **Git** (for version control)

### Installation

1. **Navigate to the docs directory:**
   ```bash
   cd /Users/kurt/GitHub/MCP-Security/modelcontextprotocol-security.io/docs/
   ```

2. **Run the setup script:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

   Or if you need to install Ruby dependencies automatically:
   ```bash
   ./setup.sh --install-deps
   ```

3. **Start the development server:**
   ```bash
   chmod +x serve.sh
   ./serve.sh
   ```

4. **Visit your site:**
   Open [http://localhost:4000](http://localhost:4000) in your browser

## 📁 Project Structure

```
docs/
├── _config.yml                 # Jekyll configuration
├── _layouts/                   # Page layouts
│   └── home.html              # Homepage layout
├── _includes/                  # Reusable components
│   └── csa-header.html        # CSA sponsorship banner
├── _sass/                      # Sass stylesheets
│   └── color_schemes/         # Color scheme definitions
│       └── csa.scss           # CSA color scheme
├── assets/                     # Static assets
│   ├── css/                   # Stylesheets
│   ├── js/                    # JavaScript files
│   └── images/                # Images and logos
├── Gemfile                     # Ruby dependencies
├── index.md                    # Homepage content
├── setup.sh                   # Setup script
├── serve.sh                   # Development server script
└── [content directories]/     # Your content sections
    ├── why/
    ├── hardening/
    ├── operations/
    ├── patterns/
    ├── audit/
    ├── tools/
    ├── vulnerability-db/
    ├── community/
    ├── blog/
    └── events/
```

## 🎨 Design Features

### CSA-Inspired Design
- **Primary Color**: #1f4e79 (CSA Blue)
- **Secondary Color**: #0066cc (Light Blue)
- **Clean Typography**: Professional sans-serif fonts
- **Responsive Design**: Mobile-first approach
- **Professional Cards**: For content sections
- **Hero Section**: Engaging homepage banner

### Just the Docs Theme
- **Navigation**: Hierarchical sidebar navigation
- **Search**: Built-in search functionality
- **Mobile Responsive**: Optimized for all devices
- **Accessibility**: WCAG compliant
- **Fast Loading**: Optimized performance

## 🛠️ Development

### Local Development
```bash
# Start development server with live reload
./serve.sh

# Build the site (for production)
bundle exec jekyll build

# Clean build artifacts
bundle exec jekyll clean
```

### Adding Content
1. **Create new pages** in the appropriate directory
2. **Add frontmatter** to define page properties:
   ```yaml
   ---
   title: "Page Title"
   parent: "Parent Section"
   nav_order: 1
   ---
   ```
3. **Write content** in Markdown
4. **Test locally** with `./serve.sh`

### Customizing Design
- **Colors**: Edit `_sass/color_schemes/csa.scss`
- **Layouts**: Modify files in `_layouts/`
- **Components**: Update `_includes/` files
- **Styles**: Add custom CSS to `assets/css/`

## 🚀 Deployment

### GitHub Pages (Automatic)
1. **Commit changes:**
   ```bash
   git add .
   git commit -m "Update site content"
   git push origin main
   ```

2. **GitHub Pages** will automatically build and deploy your site

### Manual Build
```bash
# Build for production
JEKYLL_ENV=production bundle exec jekyll build

# The built site will be in _site/
```

## 📋 Configuration

### Site Settings (`_config.yml`)
- **Site Information**: Title, description, URL
- **Theme Settings**: Color scheme, navigation
- **SEO**: Meta tags, social sharing
- **Analytics**: Google Analytics (optional)

### Navigation Structure
Navigation is automatically generated from your content structure and frontmatter. Use the `nav_order` and `parent` properties to organize your pages.

## 🎯 Content Guidelines

### Page Structure
1. **Clear Headings**: Use hierarchical headings (H1, H2, H3)
2. **Descriptive Links**: Use meaningful link text
3. **Consistent Formatting**: Follow markdown standards
4. **SEO Friendly**: Include meta descriptions

### CSA Branding
- **Acknowledge Sponsorship**: Include CSA attribution
- **Professional Tone**: Maintain professional language
- **Consistent Colors**: Use the defined color palette
- **Quality Content**: Ensure accuracy and completeness

## 🔧 Troubleshooting

### Common Issues

**Ruby/Bundler Problems:**
```bash
# Update bundler
gem install bundler

# Clean and reinstall gems
bundle clean --force
bundle install
```

**Jekyll Build Errors:**
```bash
# Clean build cache
bundle exec jekyll clean

# Build with verbose output
bundle exec jekyll build --verbose
```

**Port Already in Use:**
```bash
# Use different port
bundle exec jekyll serve --port 4001
```

### Getting Help
- **Jekyll Documentation**: https://jekyllrb.com/docs/
- **Just the Docs**: https://just-the-docs.github.io/just-the-docs/
- **GitHub Issues**: Create issues in the repository

## 📚 Resources

### Documentation
- [Jekyll Documentation](https://jekyllrb.com/docs/)
- [Just the Docs Theme](https://just-the-docs.github.io/just-the-docs/)
- [GitHub Pages](https://pages.github.com/)
- [Markdown Guide](https://www.markdownguide.org/)

### Design Resources
- [Cloud Security Alliance](https://cloudsecurityalliance.org)
- [Color Accessibility](https://webaim.org/resources/contrastchecker/)
- [Responsive Design](https://web.dev/responsive-web-design-basics/)

## 🤝 Contributing

1. **Fork the repository**
2. **Create a feature branch**
3. **Make your changes**
4. **Test locally**
5. **Submit a pull request**

## 📄 License

This project is licensed under the same terms as the MCP Security project.

---

*This Jekyll site is built for the Model Context Protocol Security project, sponsored by the [Cloud Security Alliance](https://cloudsecurityalliance.org).*
