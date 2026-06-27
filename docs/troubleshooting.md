# Troubleshooting

## Extension Fails to Load

**Symptom:** Error output when adding the extension, or it does not appear in the Extensions list.

**Solution:**
- Confirm you selected **Java** as the extension type (not Python or Ruby)
- Verify you are running a current Burp Suite (2025.2+ for the Burp AI provider) with a Java 21 runtime
- Check **Extensions > Installed > (SILENTCHAIN Community) > Errors / Output** for details
- Re-download the `.jar` if the file may be corrupted, then reload

## AI Connection Errors

**Symptom:** "Connection refused" or timeout errors in the extension output.

**Solutions by provider:**

### Burp AI
- Requires Burp Suite **Professional** with an active Burp AI subscription and available credits
- Confirm AI features are enabled in Burp and your account has credit balance

### Ollama
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama if not running
ollama serve

# Verify the model is pulled
ollama list
```

### Cloud Providers (OpenAI, Claude, Gemini, Azure)
- Verify your API key is correct and not expired
- Check the API URL matches the provider's current endpoint
- Ensure your network allows outbound HTTPS connections
- Check for rate limiting (wait and retry)

## No Findings Generated

**Symptom:** Traffic flows through Burp but no findings appear in the SILENTCHAIN Community tab.

**Solutions:**
- Verify the AI provider is connected (use **Test Connection** in Settings)
- Ensure passive analysis is enabled (it is OFF by default) and the target is in Burp's scope
- Confirm the target application returns meaningful HTTP responses (not just redirects)
- Try a different / larger AI model — smaller models may miss subtle vulnerabilities
- Right-click a request → **Analyze (SILENTCHAIN)** to force on-demand analysis

## Slow Analysis

**Symptom:** Findings take a long time to appear, or Burp feels sluggish.

**Solutions:**
- Use a smaller, faster model (e.g., `llama3.1:8b` for Ollama) or the in-process Burp AI provider
- For local Ollama, ensure your GPU is being utilized (`nvidia-smi`)
- Increase the **Request Timeout** setting if the model needs more time
- Reduce the **Max Tokens** setting to get shorter responses

## Memory Issues

**Symptom:** Burp Suite runs out of memory or becomes unresponsive during extended scans.

**Solutions:**
- Increase Burp Suite's heap size (e.g., `-Xmx4g` in the startup options)
- Tighten the safety rails (per-host rate limit, response-size cap, URL dedup) in the Advanced tab
- Clear the findings/tasks lists periodically during long sessions
- Restart Burp Suite if memory usage grows too high
