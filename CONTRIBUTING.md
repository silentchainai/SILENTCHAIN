# Contributing to SILENTCHAIN AI

Thank you for considering contributing to SILENTCHAIN AI! We welcome contributions from the community.

---

## Ways to Contribute

### 🐛 Report Bugs

Found a bug? Please create an issue with:
- Burp Suite version
- SILENTCHAIN version
- AI provider and model
- Steps to reproduce
- Expected vs actual behavior
- Error messages from Console

### 💡 Suggest Features

Have an idea? Open an issue tagged `enhancement` with:
- Clear description of the feature
- Use case and benefits
- Example implementation (if applicable)

### 📝 Improve Documentation

Help make our docs better:
- Fix typos or unclear explanations
- Add examples and tutorials
- Translate documentation
- Improve installation guides

### 🔧 Submit Code

Ready to code? Follow our development workflow below.

---

## Development Setup

### Prerequisites

- Python 2.7 (Jython)
- Burp Suite
- Git
- AI provider (Ollama recommended for development)

### Fork and Clone

```bash
# Fork the repository on GitHub
# Then clone your fork
git clone https://github.com/YOUR-USERNAME/silentchain-ai.git
cd silentchain-ai

# Add upstream remote
git remote add upstream https://github.com/yourusername/silentchain-ai.git
```

### Load in Burp

1. Open Burp Suite
2. `Extender` → `Extensions` → `Add`
3. Select your local `silentchain_ai_community.py`
4. Make changes and reload extension to test

---

## Code Style

### Python Style

Follow PEP 8 guidelines where possible (Jython 2.7 limitations apply):

```python
# Good
def analyze_request(self, message_info):
    """Analyze HTTP request for vulnerabilities."""
    pass

# Bad
def analyzeRequest(self,messageInfo):
    pass
```

### Naming Conventions

- Classes: `CamelCase`
- Functions/methods: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private methods: `_leading_underscore`

### Comments

- Use docstrings for classes and public methods
- Add inline comments for complex logic
- Keep comments concise and relevant

```python
def ask_ai(self, prompt):
    """
    Send prompt to configured AI provider.
    
    Args:
        prompt (str): Security analysis prompt
        
    Returns:
        str: AI response text or None on failure
    """
    # Implementation...
```

---

## Pull Request Process

### 1. Create Feature Branch

```bash
git checkout -b feature/amazing-feature
```

### 2. Make Changes

- Write code following style guidelines
- Add comments where needed
- Test thoroughly with multiple AI providers

### 3. Test Your Changes

- Load extension in Burp
- Test with real targets
- Verify no errors in `Extender` → `Errors`
- Check Console output
- Verify findings are created

### 4. Commit

```bash
git add .
git commit -m "Add amazing feature"
```

**Commit Message Format:**

```
<type>: <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Example:**

```
feat: Add support for custom AI models

- Allow users to specify custom model endpoints
- Add model validation before analysis
- Update settings UI with model selector

Closes #123
```

### 5. Push and Create PR

```bash
git push origin feature/amazing-feature
```

Then create a Pull Request on GitHub with:
- Clear title describing the change
- Detailed description of what and why
- Screenshots/demos if UI changes
- Link to related issues

---

## Development Guidelines

### AI Provider Integration

When adding new AI provider support:

1. Add provider test method:
```python
def _test_newprovider_connection(self):
    """Test connection to NewProvider API."""
    # Implementation
```

2. Add API request method:
```python
def _ask_newprovider(self, prompt):
    """Send request to NewProvider."""
    # Implementation
```

3. Update settings UI to include new provider
4. Update documentation with setup instructions

### UI Components

When modifying UI:
- Use existing color scheme (defined in `initUI`)
- Follow Java Swing conventions
- Test with different screen sizes
- Ensure thread safety (use `SwingUtilities.invokeLater`)

### Error Handling

Always handle errors gracefully:

```python
try:
    # Risky operation
    result = self.ask_ai(prompt)
except Exception as e:
    self.stderr.println("[!] Error: %s" % e)
    # Log to stats
    self.updateStats("errors")
    # Return safely
    return None
```

---

## Testing

### Manual Testing Checklist

Before submitting PR, verify:

- [ ] Extension loads without errors
- [ ] All AI providers tested (if modified)
- [ ] Settings UI works correctly
- [ ] Console logging displays properly
- [ ] Findings panel updates
- [ ] Statistics track correctly
- [ ] No memory leaks during extended use
- [ ] Works with both Burp Community and Pro

### Test Targets

Use these for testing:
- [DVWA](http://www.dvwa.co.uk/)
- [WebGoat](https://owasp.org/www-project-webgoat/)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)

---

## Community Guidelines

### Code of Conduct

- Be respectful and inclusive
- Help newcomers
- Accept constructive criticism
- Focus on technical merit
- No harassment or discrimination

### Getting Help

Stuck? Reach out:
- [Discord Community](https://discord.gg/silentchain)
- [GitHub Discussions](https://github.com/yourusername/silentchain-ai/discussions)
- Email: dev@silentchain.ai

---

## Release Process

(For maintainers)

### Version Numbering

Follow Semantic Versioning (SemVer):
- `MAJOR.MINOR.PATCH`
- Example: `1.2.3`

### Creating a Release

1. Update version in code
2. Update `CHANGELOG.md`
3. Create git tag
4. Build release artifacts
5. Publish to GitHub Releases
6. Announce on Discord/Twitter

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

## Recognition

All contributors will be:
- Listed in `CONTRIBUTORS.md`
- Mentioned in release notes
- Acknowledged in documentation

Thank you for making SILENTCHAIN AI better! 🚀
