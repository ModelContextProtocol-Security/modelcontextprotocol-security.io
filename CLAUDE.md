# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **Model Context Protocol Security** documentation site - a Cloud Security Alliance community project focused on security guidance for MCP deployments. The site provides comprehensive security hardening guides, operational best practices, security tools, threat intelligence, and vulnerability assessments for organizations using MCP servers and AI agents.

## Development Environment

This is a Jekyll-based static site using the "Just the Docs" theme, hosted on GitHub Pages at `https://modelcontextprotocol-security.github.io/modelcontextprotocol-security.io/`.

### Common Commands

**Setup and Dependencies:**
```bash
cd docs/
./setup.sh          # Install Ruby gems and set up Jekyll environment
./make-scripts-executable.sh  # Ensure all scripts are executable
```

**Development Server:**
```bash
cd docs/
./serve.sh          # Start development server at http://localhost:4000
```

**Maintenance and Cleanup:**
```bash
cd docs/
./setup-cleanup.sh  # Clean up temporary files and reset environment
./deploy-navigation-fix.sh  # Deploy navigation fixes for GitHub Pages
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
- `docs/index.md` - Homepage with feature cards and quick start guide
- `docs/_config.yml` - Jekyll configuration with CSA theme settings and collections
- `docs/Gemfile` - Ruby dependencies for Jekyll and plugins
- `docs/_layouts/` - Custom Jekyll layouts
- `docs/_includes/` - Reusable Jekyll components
- `docs/_sass/` - Custom SCSS styling
- `docs/assets/` - Static assets (images, CSS, JavaScript)

### Scripts and Automation
- `docs/setup.sh` - Automated environment setup and dependency installation
- `docs/serve.sh` - Development server with live reload
- `docs/make-scripts-executable.sh` - Script permission management
- `docs/setup-cleanup.sh` - Environment cleanup and reset
- `docs/deploy-navigation-fix.sh` - Navigation deployment fixes

### Content Organization

The site is organized around comprehensive security guidance for MCP deployments:

#### Core Security Sections
- **Hardening Guide** (`docs/hardening/`) - 10-part comprehensive security framework
- **Operations Guide** (`docs/operations/`) - Production deployment and operational security
- **Build Security** (`docs/build-security/`) - CI/CD pipeline security
- **Configuration Management** (`docs/configuration/`) - Secure configuration practices
- **Monitoring & Logging** (`docs/monitoring/`) - Security monitoring and incident response

#### Threat Intelligence & Vulnerability Management
- **TTPs (Tactics, Techniques, Procedures)** (`docs/ttps/`) - Comprehensive threat framework with 12 categories:
  - Prompt Injection & Manipulation
  - Tool Poisoning & Metadata Attacks
  - Data Exfiltration & Credential Theft
  - Command & Code Injection
  - Authentication & Authorization
  - Supply Chain & Dependencies
  - Context Manipulation
  - Protocol Vulnerabilities
  - Privilege & Access Control
  - Economic & Infrastructure Abuse
  - Monitoring & Operational Security
  - AI-Specific Vulnerabilities
- **TTP Matrix View** (`docs/ttps-view.md`) - Interactive matrix interface for browsing all techniques
- **Known Vulnerabilities** (`docs/known-vulnerabilities/`) - CVE database and vulnerability assessments

#### Tools & Automation
- **Audit Tools** (`docs/audit/`) - Security assessment tools and procedures
- **Reference Patterns** (`docs/patterns/`) - Architecture patterns and deployment templates
- **Automation** (`docs/automation/`) - Security automation and orchestration

#### Support Sections
- **Community Projects** (`docs/projects.md`) - Showcase of open-source MCP security tools and resources
- **Community Resources** (`docs/community/`) - Contribution guidelines and working group info
- **News** (`docs/news/`) - Security updates and announcements
- **Tools** (`docs/tools/`) - Security automation tools and utilities

### Navigation Structure
- Each major section has an `index.md` file with `has_children: true`
- Individual pages use `nav_order` for positioning within sections
- **Current navigation order**: Home (1), Why MCP Security (2), TTP Matrix View (3), MCP Security TTPs (4), etc.
- TTP Matrix View provides interactive interface for browsing all security techniques
- External links configured in `_config.yml` for GitHub and CSA resources

## Theme and Styling

- **Theme**: Just the Docs with extensive customizations
- **Custom Layouts**: Specialized layouts in `docs/_layouts/` for different content types
- **Color Scheme**: CSA-inspired theme (defined in `docs/_sass/color_schemes/csa.scss`)
- **Custom Components**: Reusable includes in `docs/_includes/` for consistent formatting
- **Homepage Styling**: Custom CSS for feature cards and navigation elements
- **TTP Matrix Styling**: Interactive matrix view with hover effects (`docs/assets/css/matrix-view.css`)
- **Project Cards**: Styled project showcase for community tools (`docs/projects.md`)
- **Clean Design**: No emojis or external framework references - professional appearance

## Content Management

### Markdown Files
- All content uses Jekyll front matter with required properties:
  - `title`: Page title
  - `nav_order`: Position in navigation
  - `has_children`: For parent pages with sub-sections
  - `parent`: For child pages (references parent page title)
- Content written in GitHub-flavored Markdown with Jekyll extensions
- Cross-references use relative links (e.g., `[link](../operations/)`)
- TTP entries follow standardized format with threat modeling details

### Site Configuration
- Site metadata and navigation in `docs/_config.yml`
- Jekyll collections configured for specialized content types
- Plugin configuration for enhanced functionality
- External resource links in `aux_links` section

### Jekyll Collections
The site uses Jekyll collections for specialized content organization:
- Custom collections may be configured for TTPs, vulnerabilities, or other structured content
- Collection configuration in `_config.yml` with output and permalink settings

## Development Workflow

### Standard Development Process
1. **Environment Setup**: Run `./setup.sh` to install dependencies and configure environment
2. **Script Permissions**: Use `./make-scripts-executable.sh` to ensure proper script permissions
3. **Local Development**: Start development server with `./serve.sh` for live reload
4. **Content Creation**: Add or edit Markdown files in appropriate directories
5. **Navigation Testing**: Verify navigation structure and cross-links work correctly
6. **Build Testing**: Test site building with `bundle exec jekyll build --verbose`
7. **Cleanup**: Use `./setup-cleanup.sh` to clean temporary files before commits
8. **Deployment**: GitHub Pages automatically builds from `docs/` directory

### Navigation Management
- Navigation is automatically generated from Jekyll front matter
- Use `deploy-navigation-fix.sh` if navigation issues occur on GitHub Pages
- Ensure consistent `nav_order` values within each section

### Content Guidelines
- Follow established naming conventions for consistency
- Use appropriate front matter for proper navigation
- Include cross-references to related content
- Maintain security-focused perspective in all content
- **No emojis or external framework references** - keep content professional
- **No references to other security frameworks** - maintain independence
- Test all internal and external links before publishing

## Key Files for Understanding the Codebase

### Configuration Files
- `docs/_config.yml` - Main Jekyll configuration, theme settings, navigation
- `docs/Gemfile` - Ruby dependencies and Jekyll plugins
- `docs/_sass/color_schemes/csa.scss` - Custom color scheme definition

### Content Structure Files  
- `docs/index.md` - Homepage with feature cards including Community Projects
- `docs/ttps-view.md` - Interactive TTP matrix view page
- `docs/projects.md` - Community projects showcase page
- `docs/*/index.md` - Section landing pages with child page listings
- Major section indexes provide navigation to sub-content

### Development Files
- `docs/setup.sh` - Primary environment setup and dependency management
- `docs/serve.sh` - Development server with optimal settings for content editing
- `docs/make-scripts-executable.sh` - Script permission management
- `docs/setup-cleanup.sh` - Environment cleanup and maintenance

## AI Assistant Guidance

### Working with This Codebase
- **Always run scripts from the `docs/` directory**
- **Use `./serve.sh` for local development** - includes live reload and optimal settings
- **Follow Jekyll front matter requirements** - pages without proper front matter won't navigate correctly
- **Maintain security focus** - all content should align with defensive security objectives
- **Test navigation changes** - verify section organization and cross-links work properly

### Content Creation Best Practices
- Use existing content as templates for formatting and structure
- Follow established naming conventions (especially for TTPs and vulnerabilities)
- Include appropriate cross-references to related content
- Ensure all external links are current and accessible
- Test content locally before suggesting publication

### Navigation and Structure
- Each major section needs an `index.md` with `has_children: true`
- Child pages must reference their parent with `parent: "Parent Page Title"`
- Use sequential `nav_order` values within each section
- External navigation links go in `_config.yml` under `aux_links`

## Community Projects Integration

The site showcases the comprehensive MCP Security ecosystem:

### GitHub Organization
- **Main Organization**: https://github.com/ModelContextProtocol-Security
- **Website Repository**: modelcontextprotocol-security.io
- **Tool Repositories**: mcpserver-audit, mcpserver-finder, mcpserver-builder, mcpserver-operator
- **Database Repositories**: vulnerability-db, audit-db

### Projects Page Structure
- **MCP Security Tools**: Expert tools for audit, discovery, development, and operations
- **Community Databases**: Vulnerability tracking and audit result databases
- **Documentation Hub**: This website and associated resources

## Security Context

This is a defensive security project exclusively focused on:
- Hardening MCP server deployments against known threats
- Operational security best practices for production environments  
- Security audit tools and vulnerability assessment procedures
- Threat intelligence and TTP analysis for defensive purposes
- Community-driven security guidance and best practices
- Open-source tool ecosystem for MCP security

**Important**: The content focuses exclusively on defensive security measures and does not include offensive security tools, techniques, or procedures. All guidance is oriented toward protecting MCP deployments and improving security posture.