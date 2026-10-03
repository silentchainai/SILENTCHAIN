# Troubleshooting

## Extension Fails to Load

**Symptom:** Error output when adding the extension, or it does not appear in the Extensions list.

**Solution:**
- Confirm you selected **Java** as the extension type (not Python or Ruby)
- Verify you are running Burp Suite Professional 2025.8 or later with a Java 21 runtime
- On Burp Suite Community Edition the extension loads, logs why in its Output tab, and stays
  idle: Community Edition and Burp Suite DAST are not supported
- Check **Extensions > Installed > (SILENTCHAIN Community Edition) > Errors / Output** for details
- Re-download the `.jar` if the file may be corrupted, then reload

## AI Is Disabled / Nothing Is Sent

**Symptom:** The Runtime Status line shows `AI: Disabled`, or Test Connection reports that AI
is disabled for SILENTCHAIN.

**Solution:**
- Enable **Use AI** for SILENTCHAIN in **Extensions > Installed**. It is off by default for
  manually loaded extensions (Burp asks when installing from the BApp Store).
- Check that AI is not turned off globally in Burp's AI settings.
- This applies to **every** provider, including Ollama: no AI request of any kind is sent
  while AI is disabled.

## AI Connection Errors

**Symptom:** "Connection refused" or timeout errors in the extension output.

**Solutions by provider:**

### Burp AI
- Requires Burp Suite **Professional** with available Burp AI credits
- Confirm **Use AI** is enabled for SILENTCHAIN and your account has credit balance

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
- Verify your API key is correct and not expired (each provider keeps its own key; make sure
  you entered it while that provider was selected)
- Check the API URL matches the provider's current endpoint
- Ensure your network allows outbound HTTPS connections
- Check for rate limiting (wait and retry)

## No Findings Generated

**Symptom:** Traffic flows through Burp but no findings appear in the SILENTCHAIN Community tab.

**Solutions:**
- Verify the AI provider is connected (use **Test Connection** in Settings)
- Ensure **Use AI** is enabled, passive analysis is enabled (it is OFF by default), the target
  is in Burp's scope, and tasks are not paused (SILENTCHAIN's or Burp's own)
- Passive analysis needs a live audit task: Burp's default live passive audit covers Proxy
  traffic. The Runtime Status line shows `Waiting for Burp Scanner (needs a live audit task)`
  until Burp first calls SILENTCHAIN's passive check. Repeater traffic is only analyzed
  automatically if a live audit task covers Repeater.
- Check the statistics: **Skipped (Duplicate)**, **Skipped (Rate Limit)** and **Skipped
  (Backlog)** show items filtered out before analysis
- Confirm the target application returns meaningful HTTP responses (not just redirects)
- Try a different / larger AI model - smaller models may miss subtle vulnerabilities
- Right-click a request → **Analyze Request (SILENTCHAIN)** to force on-demand analysis

## Tasks End in Error

**Symptom:** Tasks in the Active Tasks table show the status **Error**.

**Solution:**
- An analysis that fails with an exception logs a stack trace to **Extensions > Installed >
  (SILENTCHAIN Community Edition) > Errors**; the console also shows an `[ERROR]` line
- A provider that returns no result (for example an HTTP error or a timeout) also ends the
  task in **Error**; the provider's message is in the same Errors tab

## Slow Analysis

**Symptom:** Findings take a long time to appear, or Burp feels sluggish.

**Solutions:**
- Use a smaller, faster model (e.g., `llama3.1:8b` for Ollama) or the Burp AI provider
- For local Ollama, ensure your GPU is being utilized (`nvidia-smi`)
- Increase the **Third-party AI timeout (s)** setting (Advanced tab, default 120) if the model
  needs more time; Burp AI uses Burp's own limits
- Reduce the **Max Tokens** setting to get shorter responses

## Memory Issues

**Symptom:** Burp Suite runs out of memory or becomes unresponsive during extended scans.

**Solutions:**
- Increase Burp Suite's heap size (e.g., `-Xmx4g` in the startup options)
- Tighten the safety rails (per-host rate limit, response-size cap, URL dedup) in the Advanced tab
- Clear finished tasks periodically during long sessions (**Clear Completed**); the task list
  is also capped at 1,000 entries
- Restart Burp Suite if memory usage grows too high
