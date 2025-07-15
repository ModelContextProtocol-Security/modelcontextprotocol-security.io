# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **Model Context Protocol Security** documentation site - a Cloud Security Alliance community project focused on security guidance for MCP deployments. The site provides comprehensive security hardening guides, operational best practices, and security tools for organizations using MCP servers and AI agents.

## Development Environment

This is a Jekyll-based static site using the "Just the Docs" theme, hosted on GitHub Pages.

### Common Commands

**Setup and Dependencies:**
```bash
cd docs/
./setup.sh          # Install Ruby gems and set up Jekyll
```

**Development Server:**
```bash
cd docs/
./serve.sh          # Start development server at http://localhost:4000
```

**Manual Jekyll Commands:**
```bash
cd docs/
bundle install      # Install dependencies
bundle exec jekyll serve --host 0.0.0.0 --port 4000 --livereload --drafts --future --incremental
bundle exec jekyll build --verbose   # Build static site
```

## Project Structure

### Repository Organization
- `docs/` - Main Jekyll site directory (all content and configuration)
- `docs/index.md` - Homepage with cards and quick start guide
- `docs/_config.yml` - Jekyll configuration with CSA theme settings
- `docs/Gemfile` - Ruby dependencies
- `docs/setup.sh` - Automated setup script
- `docs/serve.sh` - Development server script

### Content Organization
The site is organized around security guidance for MCP deployments:

- **Hardening Guide** (`docs/hardening/`) - 10-part comprehensive security framework
- **Operations Guide** (`docs/operations/`) - Production deployment and operational security
- **Reference Patterns** (`docs/patterns/`) - Architecture patterns and deployment templates
- **Audit Tools** (`docs/audit/`) - Security assessment tools and procedures
- **Community Resources** (`docs/community/`) - Contribution guidelines and working group info

### Navigation Structure
- Each major section has an `index.md` file with `has_children: true`
- Individual pages use `nav_order` for positioning
- External links configured in `_config.yml` for GitHub and CSA

## Theme and Styling

- **Theme**: Just the Docs with custom CSA color scheme
- **Custom CSS**: Inline styles in `docs/index.md` for homepage cards
- **Color Scheme**: CSA-inspired (defined in `docs/_sass/color_schemes/csa.scss`)
- **Logo**: Placeholder SVG created by setup script

## Content Management

### Markdown Files
- All content uses Jekyll front matter with `title`, `nav_order`, and `has_children` properties
- Content is written in GitHub-flavored Markdown
- Cross-references use relative links (e.g., `[link](../operations/)`)

### Site Configuration
- Site metadata in `docs/_config.yml`
- Navigation configured through Jekyll front matter
- External links defined in `aux_links` section

## Development Workflow

1. **Local Development**: Use `./serve.sh` for live reload during editing
2. **Content Updates**: Edit Markdown files in respective directories
3. **Testing**: Jekyll serves at `http://localhost:4000` with live reload
4. **Deployment**: GitHub Pages automatically builds and deploys from `docs/` directory

## Security Context

This is a defensive security project focused on:
- Hardening MCP server deployments
- Operational security best practices
- Security audit tools and procedures
- Community-driven security guidance

The content focuses exclusively on defensive security measures and does not include offensive security tools or techniques.