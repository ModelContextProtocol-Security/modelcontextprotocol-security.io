---
layout: default
title: "TTP Matrix View"
permalink: /ttps-view/
nav_order: 3
---

<link rel="stylesheet" href="{{ '/assets/css/matrix-view.css' | relative_url }}">

# MCP Security TTPs Matrix

<div class="matrix-navigation">
  <a href="/ttps/" class="nav-link">← Back to Category View</a>
  <span class="matrix-description">Interactive matrix showing all MCP security techniques</span>
</div>

<div class="matrix-container">
  <div class="techniques-grid">
    <!-- Prompt Injection Techniques -->
    <div class="technique-column" data-category="prompt-injection">
      <!-- Category Header Card -->
      <div class="category-header-card">
        <a href="/ttps/prompt-injection/" class="category-link">
          <h3>Prompt Injection</h3>
          <span class="technique-count">7 techniques</span>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/prompt-injection/direct-prompt-injection/" class="technique-link">
          <div class="technique-name">Direct Prompt Injection</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/prompt-injection/indirect-prompt-injection/" class="technique-link">
          <div class="technique-name">Indirect Prompt Injection</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/prompt-injection/tool-description-poisoning/" class="technique-link">
          <div class="technique-name">Tool Description Poisoning</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/prompt-injection/context-shadowing/" class="technique-link">
          <div class="technique-name">Context Shadowing</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/prompt-injection/prompt-state-manipulation/" class="technique-link">
          <div class="technique-name">Prompt-State Manipulation</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/prompt-injection/ansi-escape-injection/" class="technique-link">
          <div class="technique-name">ANSI Escape Injection</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/prompt-injection/hidden-instructions/" class="technique-link">
          <div class="technique-name">Hidden Instructions</div>
        </a>
      </div>
    </div>

    <!-- Tool Poisoning Techniques -->
    <div class="technique-column" data-category="tool-poisoning">
      <!-- Category Header Card -->
      <div class="category-header-card">
        <a href="/ttps/tool-poisoning/" class="category-link">
          <h3>Tool Poisoning</h3>
          <span class="technique-count">8 techniques</span>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/tool-poisoning/tool-poisoning/" class="technique-link">
          <div class="technique-name">Tool Poisoning</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/tool-poisoning/tool-impersonation/" class="technique-link">
          <div class="technique-name">Tool Impersonation</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/tool-poisoning/metadata-manipulation/" class="technique-link">
          <div class="technique-name">Metadata Manipulation</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/tool-poisoning/tool-shadowing/" class="technique-link">
          <div class="technique-name">Tool Shadowing</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/tool-poisoning/tool-squatting/" class="technique-link">
          <div class="technique-name">Tool Squatting</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/tool-poisoning/tool-mutation/" class="technique-link">
          <div class="technique-name">Tool Mutation</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/tool-poisoning/tool-name-conflict/" class="technique-link">
          <div class="technique-name">Tool Name Conflict</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/tool-poisoning/preference-manipulation/" class="technique-link">
          <div class="technique-name">Preference Manipulation</div>
        </a>
      </div>
    </div>

    <!-- Data Exfiltration Techniques -->
    <div class="technique-column" data-category="data-exfiltration">
      <!-- Category Header Card -->
      <div class="category-header-card">
        <a href="/ttps/data-exfiltration/" class="category-link">
          <h3>Data Exfiltration</h3>
          <span class="technique-count">6 techniques</span>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/data-exfiltration/data-exfiltration/" class="technique-link">
          <div class="technique-name">Data Exfiltration</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/data-exfiltration/credential-exfiltration/" class="technique-link">
          <div class="technique-name">Credential Exfiltration</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/data-exfiltration/api-key-exposure/" class="technique-link">
          <div class="technique-name">API Key Exposure</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/data-exfiltration/token-theft/" class="technique-link">
          <div class="technique-name">Token Theft</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/data-exfiltration/conversation-history-exfiltration/" class="technique-link">
          <div class="technique-name">Conversation History Exfiltration</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/data-exfiltration/sensitive-information-disclosure/" class="technique-link">
          <div class="technique-name">Sensitive Information Disclosure</div>
        </a>
      </div>
    </div>

    <!-- Command Injection Techniques -->
    <div class="technique-column" data-category="command-injection">
      <!-- Category Header Card -->
      <div class="category-header-card">
        <a href="/ttps/command-injection/" class="category-link">
          <h3>Command Injection</h3>
          <span class="technique-count">7 techniques</span>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/command-injection/command-injection/" class="technique-link">
          <div class="technique-name">Command Injection</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/command-injection/code-injection/" class="technique-link">
          <div class="technique-name">Code Injection</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/command-injection/os-command-injection/" class="technique-link">
          <div class="technique-name">OS Command Injection</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/command-injection/sql-injection/" class="technique-link">
          <div class="technique-name">SQL Injection</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/command-injection/shell-command-execution/" class="technique-link">
          <div class="technique-name">Shell Command Execution</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/command-injection/output-prompt-injection/" class="technique-link">
          <div class="technique-name">Output Prompt Injection</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/command-injection/malicious-output-composition/" class="technique-link">
          <div class="technique-name">Malicious Output Composition</div>
        </a>
      </div>
    </div>

    <!-- Authentication Techniques -->
    <div class="technique-column" data-category="authentication">
      <!-- Category Header Card -->
      <div class="category-header-card">
        <a href="/ttps/authentication/" class="category-link">
          <h3>Authentication</h3>
          <span class="technique-count">8 techniques</span>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/authentication/broken-authentication/" class="technique-link">
          <div class="technique-name">Broken Authentication</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/authentication/auth-bypass-rogue-server/" class="technique-link">
          <div class="technique-name">Auth Bypass via Rogue Server</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/authentication/authorization-bypass/" class="technique-link">
          <div class="technique-name">Authorization Bypass</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/authentication/privilege-escalation/" class="technique-link">
          <div class="technique-name">Privilege Escalation</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/authentication/identity-subversion/" class="technique-link">
          <div class="technique-name">Identity Subversion</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/authentication/session-management-issues/" class="technique-link">
          <div class="technique-name">Session Management Issues</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/authentication/unauthenticated-access/" class="technique-link">
          <div class="technique-name">Unauthenticated Access</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/authentication/audit-bypass/" class="technique-link">
          <div class="technique-name">Audit Bypass</div>
        </a>
      </div>
    </div>

    <!-- Supply Chain Techniques -->
    <div class="technique-column" data-category="supply-chain">
      <!-- Category Header Card -->
      <div class="category-header-card">
        <a href="/ttps/supply-chain/" class="category-link">
          <h3>Supply Chain</h3>
          <span class="technique-count">7 techniques</span>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/supply-chain/supply-chain-attacks/" class="technique-link">
          <div class="technique-name">Supply Chain Attacks</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/supply-chain/malicious-mcp-packages/" class="technique-link">
          <div class="technique-name">Malicious MCP Packages</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/supply-chain/dependency-vulnerabilities/" class="technique-link">
          <div class="technique-name">Dependency Vulnerabilities</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/supply-chain/typosquatting/" class="technique-link">
          <div class="technique-name">Typosquatting</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/supply-chain/installer-spoofing/" class="technique-link">
          <div class="technique-name">Installer Spoofing</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/supply-chain/malicious-dependency-inclusion/" class="technique-link">
          <div class="technique-name">Malicious Dependency Inclusion</div>
        </a>
      </div>
      
      <div class="technique-card">
        <a href="/ttps/supply-chain/drift-from-upstream/" class="technique-link">
          <div class="technique-name">Drift from Upstream</div>
        </a>
      </div>
    </div>
  </div>
</div>

---

**Quick Navigation:**
- [Traditional TTP View](/ttps/) - Category-based navigation
- [Complete TTP Index](/ttps/) - Full documentation and guides

<script>
// Add category highlighting on hover
document.addEventListener('DOMContentLoaded', function() {
    const headers = document.querySelectorAll('.category-header');
    const columns = document.querySelectorAll('.technique-column');
    
    headers.forEach(header => {
        header.addEventListener('mouseenter', function() {
            const category = this.dataset.category;
            const column = document.querySelector(`[data-category="${category}"].technique-column`);
            if (column) {
                this.classList.add('active');
                column.classList.add('active');
            }
        });
        
        header.addEventListener('mouseleave', function() {
            const category = this.dataset.category;
            const column = document.querySelector(`[data-category="${category}"].technique-column`);
            if (column) {
                this.classList.remove('active');
                column.classList.remove('active');
            }
        });
    });
});
</script>