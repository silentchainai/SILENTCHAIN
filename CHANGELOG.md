# Changelog - SILENTCHAIN AI Community Edition

All notable changes to the SILENTCHAIN AI Community Edition will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Stream AI responses for faster perceived performance
- Support for custom AI models (local fine-tuned models)
- Export findings to PDF/HTML reports
- Integration with CI/CD pipelines
- Custom vulnerability templates

---

## [1.0.8] - 2025-01-31

### Changed
- **Context menu simplified** - "SILENTCHAIN - Analyze Request" → "Analyze Request"
  - Less redundant, cleaner
  - Burp already shows extension name in menu structure
- **AI Provider dropdown now auto-updates API URL**
  - Select "Ollama" → URL changes to `http://localhost:11434`
  - Select "OpenAI" → URL changes to `https://api.openai.com/v1`
  - Select "Claude" → URL changes to `https://api.anthropic.com/v1`
  - Select "Gemini" → URL changes to `https://generativelanguage.googleapis.com/v1`
  - Makes provider switching instant and error-free
  - Can still manually edit URL if using custom endpoints

### Technical Details
- Added `ProviderChangeListener` class in Settings dialog
- Listener updates API URL field when provider dropdown changes
- Default URLs map: Ollama, OpenAI, Claude, Gemini
- Context menu item shortened from 31 chars to 15 chars

### User Impact
- Faster provider switching (no manual URL entry)
- Less chance of typos in API URLs
- Cleaner context menu
- More intuitive Settings dialog

---

## [1.0.7] - 2025-01-31

### Fixed
- **Removed all Unicode characters** - Fixes unreadable boxes/squares on some systems
  - Settings button: "⚙ Settings" → "Settings"
  - Upgrade button: "🚀 Upgrade to Professional" → "Upgrade to Professional"
  - Debug button: "🔍 Run Task Diagnostics" → "Run Task Diagnostics"
  - Upgrade notice bullets: "•" → "-"
  - Warning symbols: "⚠" → "WARNING:"
  - Checkmarks: "✓" → "OK", "✗" → "X"
  - All text now pure ASCII for maximum compatibility

### Changed
- **Widened Settings dialog** - 600px → 750px
  - Accommodates long model names (e.g., "deepseek-r1:671b-cloud-instruct-q4_K_M")
  - Prevents text from being cut off or pushing window off-screen
  - Better visibility for all settings fields

### Technical Details
- Removed Unicode characters: ⚙ 🚀 🔍 • ⚠ ✓ ✗
- Settings dialog size: 600x500 → 750x500 pixels
- All button labels now ASCII only
- All console messages now ASCII only
- Better compatibility with non-UTF8 terminals

### User Impact
- No more unreadable box/square characters in UI
- Settings dialog properly sized for long model names
- Cleaner, more professional appearance
- Works on all systems regardless of font support

---

## [1.0.6] - 2025-01-31

### Changed
- **Increased timeout maximum to 99999 seconds** (27.7 hours)
  - Previously: 300 seconds (5 minutes) max
  - Now: 99999 seconds (almost 28 hours) max
  - Min still 10 seconds
  - Useful for extremely large AI models or slow connections
- **Moved "Debug Tasks" button to Settings → Advanced**
  - No longer clutters top control panel
  - Now accessible via Settings dialog
  - Button: "🔍 Run Task Diagnostics"
  - Includes help text explaining function

### Fixed
- **UTF-8 decoding errors for binary responses** - Critical fix
  - Error: `'utf-8' codec can't decode byte 0x9c in position 72`
  - Now uses Burp's `bytesToString()` helper for safe conversion
  - Gracefully handles binary content (images, PDFs, etc.)
  - Shows `[Binary/non-UTF8 content]` instead of crashing
  - Prevents task from getting stuck on binary responses
  - Debug logging shows decode errors in verbose mode

### Technical Details
- Timeout validation: `10 <= timeout <= 99999`
- UI change: Control panel now has 5 buttons (was 6)
  - Settings, Clear Completed, Cancel All, Pause All, Upgrade
  - Debug Tasks moved to Settings → Advanced tab
- Binary content handling:
  - Uses `self.helpers.bytesToString()` instead of `.tostring()`
  - Catches all decode exceptions
  - Logs decode errors in verbose mode
  - Falls back to placeholder text
- Timeout help text updated to show new range

### User Impact
- **No more stuck tasks on binary content** (images, PDFs, zips, etc.)
- **Can set very long timeouts** for slow models/connections
- **Cleaner UI** - one less button in control panel

---

## [1.0.5] - 2025-01-31

### Added
- **Persistent configuration** - Settings now saved to disk automatically
  - File: `~/.silentchain_config.json` (in user's home directory)
  - Auto-loads on extension startup
  - Saves on every Settings → Save
  - Includes: AI provider, API URL, API key, model, max tokens, timeout, verbose mode
- **Equal window sizing on startup** - UI panels now split evenly (33.33% each)
  - Active Tasks: 33%
  - Findings: 33%
  - Console: 33%
  - Previously: Tasks 70%, Findings 21%, Console 9%

### Fixed
- **Robust JSON parsing** - Comprehensive repair for malformed AI responses
  - Fixes unterminated strings automatically
  - Adds missing closing quotes
  - Removes trailing commas
  - Ensures valid array structure
  - Extracts valid objects from partially malformed JSON
  - Multiple fallback strategies
  - Better error messages with debug output
- **Improved error handling** - Tasks no longer silently fail on JSON errors
  - Clear error status in Active Tasks: "Error (JSON Parse Failed)"
  - Detailed error logging to Console
  - Shows first 1000 chars of failed response in verbose mode

### Changed
- Configuration is now persistent across Burp Suite restarts
- UI layout more balanced for better visibility
- JSON repair attempts multiple strategies before giving up
- Error messages more descriptive and actionable

### Technical Details
- Added `load_config()` method - loads `~/.silentchain_config.json` on startup
- Added `save_config()` method - saves all settings to JSON file
- Config file includes metadata: version, last_saved timestamp
- JSON repair strategies:
  1. Fix unterminated strings (add closing quotes)
  2. Remove trailing commas before brackets
  3. Ensure valid array structure
  4. Extract valid objects from malformed response
- Split pane resize weights changed: 0.33 (Tasks), 0.50 (Findings/Console split)
- Divider locations set explicitly on startup

### Configuration File Format
```json
{
  "ai_provider": "Ollama",
  "api_url": "http://localhost:11434",
  "api_key": "",
  "model": "deepseek-r1:latest",
  "max_tokens": 2048,
  "ai_request_timeout": 60,
  "verbose": true,
  "version": "1.0.5",
  "last_saved": "2025-01-31 14:30:00"
}
```

---

## [1.0.4] - 2025-01-31

### Added
- **"Cancel All Tasks" button** - Emergency kill switch to cancel all running/queued tasks
- **"Pause All Tasks" button** - Pause/resume all active tasks at once
- **"Debug Tasks" button** - Comprehensive task diagnostics and stuck task detection
- **Automatic stuck task detection** - Auto-checks every 30 seconds for tasks stuck >5 minutes
  - Logs warnings to console automatically
  - Provides diagnostic recommendations
- **Enhanced task status colors** - Visual indicators for Cancelled, Paused, Queued states
  - Cancelled: Dark red (bold)
  - Paused: Dark yellow (bold)
  - Queued: Gray
  - Error: Red (bold)

### Changed
- Control panel now includes 6 buttons (Settings, Clear, Cancel All, Pause All, Debug, Upgrade)
- Task status renderer shows more states with better visual distinction
- Auto-refresh timer now checks for stuck tasks in addition to UI updates

### Fixed
- Better visibility for stuck/stalled tasks
- Improved task state management
- Enhanced debugging capabilities for troubleshooting queue issues

### Technical Details
- Added `cancelAllTasks()` method - sets all active tasks to "Cancelled" status
- Added `pauseAllTasks()` method - toggles pause/resume for all active tasks
- Added `debugTasks()` method - generates detailed diagnostic report with:
  - Task counts (total, active, queued, stuck)
  - Active task details (type, status, duration, URL)
  - Queued task details
  - Stuck task warnings (>5 minutes)
  - Threading status (semaphore, rate limit, last request)
  - Diagnostic recommendations
- Added `check_stuck_tasks()` method - automatic background monitoring
- Enhanced `StatusCellRenderer` with 7 distinct states

### Diagnostics Report Includes
- Total task count
- Active/Queued/Stuck breakdown
- Per-task details: ID, Type, Status, Duration, URL
- Threading diagnostics
- Recommended actions for stuck tasks
- Common causes and solutions

---

## [1.0.3] - 2025-01-31

### Fixed
- **Context menu forced re-analysis not working** - Fixed deduplication blocking context menu requests
  - Added `analyze_forced()` method that bypasses deduplication cache
  - Context menu now properly forces fresh analysis of already-analyzed requests
  - Added `bypass_dedup` parameter to `_perform_analysis()` method
  - Verbose logging shows `[FORCE] Bypassing deduplication` for context menu requests

### Changed
- Context menu analysis now shows `Analyzing (Forced)` status in Active Tasks
- Better logging for forced re-analysis operations

### Technical Details
- Created new `analyze_forced()` method for context menu
- Updated `_perform_analysis()` to accept `bypass_dedup=False` parameter
- Context menu threads now call `analyze_forced()` instead of `analyze()`
- Deduplication cache check skipped when `bypass_dedup=True`

---

## [1.0.2] - 2025-01-31

### Fixed
- **CRITICAL**: Fixed unicode format error `%d format: a number is required, not unicode`
  - Added explicit `int()` conversion for all `%d` format strings
  - Fixed AI confidence value parsing from JSON
  - Fixed timeout value formatting in error messages
  - Fixed stats logging (created/skipped_dup/skipped_low_conf counters)
- Improved error handling for JSON parsing with unicode values

### Changed
- Enhanced error messages to be more descriptive
- Settings logging now shows all saved values for verification

### Technical Details
- Added safe integer conversion in `_perform_analysis()` for `ai_conf` values
- Wrapped timeout values in `int()` for error message formatting
- Added explicit `int()` conversion in verbose stats logging

---

## [1.0.1] - 2025-01-31

### Added
- **Configurable AI Request Timeout** setting (default: 60 seconds, range: 10-300)
  - New field in Settings → Advanced tab
  - Helps prevent timeout errors with large/slow models
- **Automatic Retry Logic** for Ollama requests
  - Retries failed requests up to 2 times
  - 2-second delay between retries
  - Only retries timeout errors (not auth/network errors)
- Comprehensive timeout troubleshooting guide (`TIMEOUT_TROUBLESHOOTING.md`)

### Changed
- Reduced default timeout from 120 seconds to 60 seconds (more reasonable)
- Improved error messages for timeout failures
  - Shows retry attempts: `[!] Request timeout, retrying... (1/2)`
  - Suggests solutions: `Try increasing timeout in Settings or using a faster model`
  - Logs timeout value in final error message

### Fixed
- Timeout errors with large AI models (deepseek-r1:671b)
- Network timeout handling across all AI providers (Ollama, OpenAI, Claude, Gemini)

### Technical Details
- Added `AI_REQUEST_TIMEOUT` configuration variable
- Updated `_ask_ollama()` with retry loop and timeout handling
- Updated `_ask_openai()`, `_ask_claude()`, `_ask_gemini()` with configurable timeout
- All providers now use `self.AI_REQUEST_TIMEOUT` instead of hardcoded 120 seconds

---

## [1.0.0] - 2025-01-31

### Initial Release - Community Edition

### Added
- **AI-Powered Passive Security Analysis**
  - Real-time vulnerability detection during browsing
  - OWASP Top 10 coverage
  - CWE and OWASP mappings for all findings
- **Multi-AI Provider Support**
  - Ollama (local, free)
  - OpenAI (GPT-4, GPT-3.5-turbo)
  - Claude (Anthropic)
  - Google Gemini
- **Professional User Interface**
  - Statistics panel with real-time metrics
  - Active Tasks table with task management
  - Findings panel with severity/confidence filtering
  - Console panel with auto-scroll and timestamps
- **Smart Deduplication**
  - URL-based deduplication (prevents re-analyzing same requests)
  - Finding-based deduplication (prevents duplicate issues)
  - Hash-based caching for performance
- **Comprehensive Settings**
  - AI Provider configuration (provider, API URL, API key)
  - Model selection with refresh capability
  - Max Tokens configuration (512-4096)
  - Verbose logging toggle
  - Test Connection button
- **Context Menu Integration**
  - Right-click any request → "SILENTCHAIN - Analyze Request"
  - Debounce protection (prevents duplicate analysis)
  - Automatic request sending if no response available
- **Rate Limiting**
  - 4-second delay between requests (prevents API overload)
  - Automatic queuing and processing
- **Advanced Analysis Features**
  - Parameter analysis (URL, body, cookies)
  - Request/response header analysis
  - Response body pattern matching
  - Confidence scoring (Certain, Firm, Tentative)
  - Severity levels (High, Medium, Low, Information)
- **Professional Reporting**
  - Detailed vulnerability descriptions
  - Affected parameters identification
  - CWE links to MITRE documentation
  - OWASP category mappings
  - Remediation guidance
- **Scope Management**
  - Respects Burp Suite target scope
  - Only analyzes in-scope URLs
  - Clear scope rejection messages

### Security Features
- Passive-only scanning (no active payloads)
- Privacy-focused (all data stays local with Ollama)
- No data sent to third parties (when using Ollama)

### Performance
- Efficient threading (daemon threads)
- Semaphore-based request queuing
- Auto-refresh UI (2-second intervals)
- Console message truncation (keeps last 1000 messages)

### Documentation
- Comprehensive README with quick start
- Detailed installation guide (INSTALLATION.md)
- 5-minute quick start guide (QUICKSTART.md)
- Contributing guidelines (CONTRIBUTING.md)
- Settings verification guide (SETTINGS_VERIFICATION.md)

### Known Limitations
- **Community Edition does not include:**
  - Phase 2 active verification
  - WAF detection and evasion
  - Advanced payload libraries (OWASP, custom)
  - Out-of-band (OOB) testing
  - Burp Intruder integration
  - Automated fuzzing
  - Priority support

### Technical Specifications
- **Language**: Python 2.7 (Jython)
- **Framework**: Burp Suite Extension API
- **UI**: Java Swing
- **Threading**: Python threading module
- **JSON Parsing**: Python json module
- **HTTP**: urllib2
- **Hashing**: hashlib (MD5)

### System Requirements
- Burp Suite Community/Professional 2023.x or newer
- Java 8 or higher
- Python 2.7 (Jython) - included with Burp Suite
- 4GB RAM minimum (8GB+ recommended for AI models)
- Internet connection (for cloud AI providers)
- OR Ollama installed locally (for free, offline use)

### Default Configuration
- **AI Provider**: Ollama
- **API URL**: http://localhost:11434
- **Model**: deepseek-r1:latest
- **Max Tokens**: 2048
- **Request Timeout**: 60 seconds
- **Verbose Logging**: Enabled
- **Rate Limit**: 4 seconds between requests

### File Structure
```
silentchain_ai_community.py    # Main extension file (1549 lines)
README.md                       # Project documentation
INSTALLATION.md                 # Setup guide
QUICKSTART.md                   # 5-minute guide
CONTRIBUTING.md                 # Development guide
LICENSE                         # MIT License
CHANGELOG.md                    # This file
```

### Statistics Tracked
- Total Requests
- Analyzed Requests
- Skipped (Duplicate)
- Skipped (Rate Limit)
- Skipped (Low Confidence)
- Findings Created
- Errors

### Upgrade Path
Community Edition users can upgrade to Professional Edition for:
- Active security testing with exploit payloads
- WAF detection and bypass techniques
- Advanced vulnerability verification
- Out-of-band attack detection
- Automated fuzzing workflows
- Priority support and updates

Visit https://silentchain.ai for upgrade options.

---

## Version Numbering Scheme

**Format**: `MAJOR.MINOR.PATCH`

- **MAJOR**: Incompatible API changes, major feature additions
- **MINOR**: New features, backward-compatible
- **PATCH**: Bug fixes, minor improvements

**Examples**:
- `1.0.0` - Initial stable release
- `1.0.1` - Bug fix (timeout handling)
- `1.1.0` - New feature (export reports)
- `2.0.0` - Major change (Phase 2 in Community)

---

## Release Types

### Stable Releases
- Fully tested
- Production-ready
- Semantic versioning
- Tagged in Git
- Release notes

### Beta Releases
- Format: `X.Y.Z-beta.N`
- Example: `1.1.0-beta.1`
- For testing new features
- May have bugs
- Community feedback requested

### Release Candidates
- Format: `X.Y.Z-rc.N`
- Example: `1.1.0-rc.1`
- Final testing before stable
- Feature-complete
- Only critical bugs fixed

---

## How to Read This Changelog

### Categories

**Added** - New features, capabilities, or documentation
**Changed** - Changes to existing functionality
**Deprecated** - Features that will be removed in future versions
**Removed** - Features that have been removed
**Fixed** - Bug fixes and error corrections
**Security** - Security-related fixes and improvements

### Severity Indicators

🔴 **CRITICAL** - Requires immediate attention, breaks functionality
🟠 **HIGH** - Important fix, should upgrade soon
🟡 **MEDIUM** - Notable improvement, upgrade recommended
🟢 **LOW** - Minor enhancement, upgrade optional

### Examples from this Changelog

- 🔴 **CRITICAL**: Unicode format error (v1.0.2) - Extension would crash
- 🟠 **HIGH**: Timeout configuration (v1.0.1) - Prevents common failures
- 🟢 **LOW**: Enhanced error messages (v1.0.2) - Better UX

---

## Contributing

Found a bug? Have a feature request? See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License - See [LICENSE](LICENSE) file for details.

---

## Support

- **Community Support**: GitHub Issues
- **Documentation**: https://github.com/silentchain-ai/community
- **Professional Support**: support@silentchain.ai (Professional Edition only)

---

## Acknowledgments

- Burp Suite by PortSwigger
- Ollama team for local AI inference
- OpenAI, Anthropic, Google for cloud AI APIs
- OWASP for vulnerability categorization
- MITRE for CWE database
- Security research community

---

*Last Updated: 2025-01-31*
