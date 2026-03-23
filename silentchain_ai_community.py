# -*- coding: utf-8 -*-
# Burp Suite Python Extension: SILENTCHAIN AI - COMMUNITY EDITION
# Version: 1.1.1
# Release Date: 2025-02-04
# License: MIT License
# Build-ID: bb90850f-1d2e-4d12-852e-842527475b37
#
# COMMUNITY EDITION - AI-Powered Security Scanner
#
# This community edition provides:
# - AI-powered passive security analysis
# - OWASP Top 10 vulnerability detection
# - Real-time threat identification
# - Professional reporting with CWE/OWASP mappings
#
# Professional Edition adds:
# - Phase 2 active verification with exploit payloads
# - WAF detection and evasion
# - Advanced payload libraries
# - Out-of-band (OOB) testing
# - Automated fuzzing with Burp Intruder integration
#
# Changelog:
# v1.1.1 (2025-02-04) - Fix Settings freeze and slow startup: move network calls off EDT to background threads
# v1.1.0 (2025-02-04) - Fix UI hang on Linux: dirty-flag refresh guard, incremental console, remove EDT lock contention
# v1.0.9 (2025-02-02) - Skip static files (js,css,images,fonts), passive scan toggle, taller Settings dialog
# v1.0.8 (2025-01-31) - Minor fixes and improvements
# v1.0.7 (2025-01-31) - Removed Unicode chars, widened Settings dialog
# v1.0.6 (2025-01-31) - Fixed UTF-8 decode errors, timeout max 99999s, moved Debug to Settings
# v1.0.5 (2025-01-31) - Persistent config, equal window sizing, robust JSON parsing
# v1.0.4 (2025-01-31) - Added Cancel/Pause All, Debug Tasks, auto stuck detection
# v1.0.3 (2025-01-31) - Fixed context menu forced re-analysis
# v1.0.2 (2025-01-31) - Fixed unicode format errors, improved error handling
# v1.0.1 (2025-01-31) - Added configurable timeout, retry logic
# v1.0.0 (2025-01-31) - Initial stable release

from burp import IBurpExtender, IHttpListener, IScannerCheck, IScanIssue, ITab, IContextMenuFactory
from java.io import PrintWriter
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Dimension, Font, Color, FlowLayout
from javax.swing import JPanel, JScrollPane, JTextArea, JTable, JLabel, JSplitPane, BorderFactory, SwingUtilities, JButton, BoxLayout, Box, JMenuItem
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.lang import Runnable
from java.util import ArrayList
from java.util.concurrent import Executors, TimeUnit
import json
import threading
import urllib2
import urllib
import time
import hashlib
from datetime import datetime

VALID_SEVERITIES = {
    "high": "High", "medium": "Medium", "low": "Low",
    "information": "Information", "informational": "Information",
    "info": "Information", "inform": "Information"
}

def map_confidence(ai_confidence):
    if ai_confidence < 50: return None
    elif ai_confidence < 75: return "Tentative"
    elif ai_confidence < 90: return "Firm"
    else: return "Certain"

# Custom PrintWriter wrapper to capture console output
class ConsolePrintWriter:
    def __init__(self, original_writer, extender_ref):
        self.original = original_writer
        self.extender = extender_ref
    
    def println(self, message):
        self.original.println(message)
        if hasattr(self.extender, 'log_to_console'):
            try:
                self.extender.log_to_console(str(message))
            except:
                pass
    
    def print_(self, message):
        self.original.print_(message)
    
    def write(self, data):
        self.original.write(data)
    
    def flush(self):
        self.original.flush()

class AnalyzeTask(Runnable):
    """Runnable wrapper for submitting analysis tasks to thread pool."""
    def __init__(self, extender, messageInfo, url_str, task_id):
        self.extender = extender
        self.messageInfo = messageInfo
        self.url_str = url_str
        self.task_id = task_id
    
    def run(self):
        self.extender.analyze(self.messageInfo, self.url_str, self.task_id)

class ForcedAnalyzeTask(Runnable):
    """Runnable wrapper for forced analysis (context menu) that bypasses deduplication."""
    def __init__(self, extender, messageInfo, url_str, task_id):
        self.extender = extender
        self.messageInfo = messageInfo
        self.url_str = url_str
        self.task_id = task_id
    
    def run(self):
        self.extender.analyze_forced(self.messageInfo, self.url_str, self.task_id)

class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        
        # Store original writers
        original_stdout = PrintWriter(callbacks.getStdout(), True)
        original_stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Wrap to capture console output
        self.stdout = ConsolePrintWriter(original_stdout, self)
        self.stderr = ConsolePrintWriter(original_stderr, self)

        # Version Information
        self.VERSION = "1.1.4"
        self.EDITION = "Community"
        self.RELEASE_DATE = "2026-03-18"
        self.BUILD_ID = "bb90850f-1d2e-4d12-852e-842527475b37"
        self.CONFIG_VERSION = 2  # Increment this when config format changes

        callbacks.setExtensionName("SILENTCHAIN AI - %s Edition v%s" % (self.EDITION, self.VERSION))
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)

        # Configuration file path (in user's home directory)
        import os
        self.config_file = os.path.join(os.path.expanduser("~"), ".silentchain_config.json")
        self.vuln_cache_file = os.path.join(os.path.expanduser("~"), ".silentchain_vuln_cache.json")
        
        # AI Provider Settings (defaults - will be overridden by saved config)
        self.AI_PROVIDER = "Ollama"  # Options: Ollama, OpenAI, Claude, Gemini, Azure Foundry
        self.API_URL = "http://localhost:11434"
        self.API_KEY = ""  # For OpenAI, Claude, Gemini, Azure Foundry
        self.MODEL = "deepseek-r1:latest"
        self.AZURE_API_VERSION = "2024-06-01"  # Can be overridden via OPENAI_API_VERSION or AZURE_OPENAI_API_VERSION
        self.MAX_TOKENS = 2048
        self.AI_REQUEST_TIMEOUT = 60  # Timeout for AI requests in seconds (default: 60)
        self.available_models = []

        self.VERBOSE = True
        self.THEME = "Light"  # Options: Light, Dark
        self.PASSIVE_SCANNING_ENABLED = True  # Enable/disable passive scanning (context menu still works)

        # File extensions to skip during analysis (static/non-security-relevant files)
        self.SKIP_EXTENSIONS = ["js", "gif", "jpg", "png", "ico", "css", "woff", "woff2", "ttf", "svg"]

        # Load saved configuration (if exists)
        self.load_config()
        self.apply_environment_config()
        
        # UI refresh control
        self._ui_dirty = True           # Flag: data changed since last refresh
        self._refresh_pending = False   # Guard: refresh already queued on EDT
        self._last_console_len = 0      # Track console length for incremental append
        
        # Cache persistence control (async write-behind)
        self._cache_dirty = False       # Flag: cache changed since last save

        # Console tracking for UI panel
        self.console_messages = []
        self.console_lock = threading.Lock()
        self.max_console_messages = 1000
        
        # Findings tracking for Findings panel
        self.findings_list = []
        self.findings_lock_ui = threading.Lock()
        
        self.findings_cache = {}
        self.findings_lock = threading.Lock()

        # Persistent vulnerability cache to reduce repeat AI calls across sessions
        self.vuln_cache = {}
        self.vuln_cache_lock = threading.Lock()
        
        # Context menu debounce
        self.context_menu_last_invoke = {}
        self.context_menu_debounce_time = 1.0
        self.context_menu_lock = threading.Lock()
        
        self.processed_urls = set()
        self.url_lock = threading.Lock()
        
        # Per-host semaphores + global pool cap (fix semaphore bottleneck)
        self.host_semaphores = {}
        self.host_semaphore_lock = threading.Lock()
        self.global_semaphore = threading.Semaphore(5)  # max 5 concurrent AI calls
        
        # Thread pool for bounded analysis tasks (instead of unbounded thread spawning)
        self.thread_pool = Executors.newFixedThreadPool(5)
        
        self.last_request_time = 0
        self.min_delay = 4.0

        # Task tracking
        self.tasks = []
        self.tasks_lock = threading.Lock()
        self.stats = {
            "total_requests": 0,
            "analyzed": 0,
            "cached_reused": 0,
            "skipped_duplicate": 0,
            "skipped_rate_limit": 0,
            "skipped_low_confidence": 0,
            "findings_created": 0,
            "errors": 0
        }
        self.stats_lock = threading.Lock()

        # Create UI
        self.initUI()

        # Load persistent cache after UI exists so status labels can reflect it
        self.load_vuln_cache()
        
        self.log_to_console("=== SILENTCHAIN AI - Community Edition Initialized ===")
        self.log_to_console("Console panel is active and logging...")
        
        # Force immediate UI refresh
        self.refreshUI()
        
        # Display logo
        self.print_logo()
        
        self.stdout.println("[+] Version: %s (Released: %s)" % (self.VERSION, self.RELEASE_DATE))
        self.stdout.println("[+] Edition: Community (Passive Analysis Only)")
        self.stdout.println("[+] AI Provider: %s" % self.AI_PROVIDER)
        self.stdout.println("[+] API URL: %s" % self.API_URL)
        self.stdout.println("[+] Model: %s" % self.MODEL)
        self.stdout.println("[+] Max Tokens: %d" % self.MAX_TOKENS)
        self.stdout.println("[+] Request Timeout: %d seconds" % self.AI_REQUEST_TIMEOUT)
        self.stdout.println("[+] Deduplication: ENABLED")
        self.stdout.println("")
        self.stdout.println("[*] COMMUNITY EDITION - Passive scanning only")

        # Test AI connection in background thread (non-blocking startup)
        def _startup_connection_test():
            connection_ok = self.test_ai_connection()
            if not connection_ok:
                self.stderr.println("\n[!] WARNING: AI connection test failed!")
                self.stderr.println("[!] Extension will not function properly until connection is established.")
                self.stderr.println("[!] Please check Settings and verify your AI configuration.")
        _conn_thread = threading.Thread(target=_startup_connection_test)
        _conn_thread.setDaemon(True)
        _conn_thread.start()

        # Add UI tab
        callbacks.addSuiteTab(self)
        
        # Start auto-refresh timer for Console
        self.start_auto_refresh_timer()

    def initUI(self):
        # Main panel
        self.panel = JPanel(BorderLayout())
        
        # Top panel with stats
        topPanel = JPanel()
        topPanel.setLayout(BoxLayout(topPanel, BoxLayout.Y_AXIS))
        topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # Title
        titleLabel = JLabel("SILENTCHAIN AI - Community Edition v%s" % self.VERSION)
        titleLabel.setFont(Font("Monospaced", Font.BOLD, 16))
        titlePanel = JPanel()
        titlePanel.add(titleLabel)
        topPanel.add(titlePanel)
        
        # Edition notice
        editionLabel = JLabel("AI-Powered OWASP Top 10 Vulnerability Scanning for Burp Suite")
        editionLabel.setFont(Font("Dialog", Font.ITALIC, 12))
        editionLabel.setForeground(Color(0xD5, 0x59, 0x35))
        editionPanel = JPanel()
        editionPanel.add(editionLabel)
        topPanel.add(editionPanel)

        # Status strip (organized quick status at top)
        statusPanel = JPanel(GridBagLayout())
        statusPanel.setBorder(BorderFactory.createTitledBorder("Runtime Status"))
        statusGbc = GridBagConstraints()
        statusGbc.insets = Insets(3, 8, 3, 8)
        statusGbc.anchor = GridBagConstraints.WEST

        statusGbc.gridx = 0
        statusGbc.gridy = 0
        statusPanel.add(JLabel("Provider:"), statusGbc)
        statusGbc.gridx = 1
        self.providerStatusLabel = JLabel(self.AI_PROVIDER)
        self.providerStatusLabel.setFont(Font("Monospaced", Font.BOLD, 11))
        statusPanel.add(self.providerStatusLabel, statusGbc)

        statusGbc.gridx = 2
        statusPanel.add(JLabel("Model:"), statusGbc)
        statusGbc.gridx = 3
        self.modelStatusLabel = JLabel(self.MODEL)
        self.modelStatusLabel.setFont(Font("Monospaced", Font.BOLD, 11))
        statusPanel.add(self.modelStatusLabel, statusGbc)

        statusGbc.gridx = 4
        statusPanel.add(JLabel("Passive Scan:"), statusGbc)
        statusGbc.gridx = 5
        self.scanStatusLabel = JLabel("Enabled" if self.PASSIVE_SCANNING_ENABLED else "Disabled")
        self.scanStatusLabel.setFont(Font("Monospaced", Font.BOLD, 11))
        statusPanel.add(self.scanStatusLabel, statusGbc)

        statusGbc.gridx = 6
        statusPanel.add(JLabel("Cache Entries:"), statusGbc)
        statusGbc.gridx = 7
        self.cacheStatusLabel = JLabel("0")
        self.cacheStatusLabel.setFont(Font("Monospaced", Font.BOLD, 11))
        statusPanel.add(self.cacheStatusLabel, statusGbc)

        topPanel.add(statusPanel)

        topPanel.add(Box.createRigidArea(Dimension(0, 10)))
        
        # Stats panel
        statsPanel = JPanel(GridBagLayout())
        statsPanel.setBorder(BorderFactory.createTitledBorder("Statistics"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 10, 5, 10)
        gbc.anchor = GridBagConstraints.WEST
        
        self.statsLabels = {}
        statNames = [
            ("total_requests", "Total Requests:"),
            ("analyzed", "Analyzed:"),
            ("cached_reused", "Reused (Cache):"),
            ("skipped_duplicate", "Skipped (Duplicate):"),
            ("skipped_rate_limit", "Skipped (Rate Limit):"),
            ("skipped_low_confidence", "Skipped (Low Confidence):"),
            ("findings_created", "Findings Created:"),
            ("errors", "Errors:")
        ]
        
        row = 0
        for key, label in statNames:
            gbc.gridx = (row % 4) * 2
            gbc.gridy = row / 4
            statsPanel.add(JLabel(label), gbc)
            
            gbc.gridx = (row % 4) * 2 + 1
            valueLabel = JLabel("0")
            valueLabel.setFont(Font("Monospaced", Font.BOLD, 12))
            statsPanel.add(valueLabel, gbc)
            self.statsLabels[key] = valueLabel
            row += 1
        
        topPanel.add(statsPanel)
        
        # Control panel (organized in two rows)
        controlPanel = JPanel()
        controlPanel.setLayout(BoxLayout(controlPanel, BoxLayout.Y_AXIS))
        primaryControls = JPanel(FlowLayout(FlowLayout.LEFT, 8, 2))
        secondaryControls = JPanel(FlowLayout(FlowLayout.LEFT, 8, 2))
        
        # Start/Stop Scanning button
        self.scanningButton = JButton("Stop Scanning", actionPerformed=self.toggleScanning)
        self.scanningButton.setBackground(Color(0x2E, 0xCC, 0x71))
        self.scanningButton.setForeground(Color.WHITE)
        self.scanningButton.setOpaque(True)
        
        # Export Findings button
        self.exportButton = JButton("Export Findings (CSV)", actionPerformed=self.exportFindings)
        self.exportButton.setBackground(Color(0x3, 0x49, 0xA3))
        self.exportButton.setForeground(Color.WHITE)
        self.exportButton.setOpaque(True)
        
        # Settings button
        self.settingsButton = JButton("Settings", actionPerformed=self.openSettings)
        
        self.clearButton = JButton("Clear Completed", actionPerformed=self.clearCompleted)
        
        # Cancel/Pause all buttons (kill switches)
        self.cancelAllButton = JButton("Cancel All Tasks", actionPerformed=self.cancelAllTasks)
        
        self.pauseAllButton = JButton("Pause All Tasks", actionPerformed=self.pauseAllTasks)
        
        primaryControls.add(self.scanningButton)
        primaryControls.add(self.exportButton)
        primaryControls.add(self.settingsButton)
        primaryControls.add(self.clearButton)

        secondaryControls.add(self.cancelAllButton)
        secondaryControls.add(self.pauseAllButton)

        controlPanel.add(primaryControls)
        controlPanel.add(secondaryControls)
        topPanel.add(controlPanel)

        self._sync_scanning_button()
        
        self.panel.add(topPanel, BorderLayout.NORTH)
        
        # Split pane for tasks and findings - equal sizing (33.33% each)
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        splitPane.setResizeWeight(0.33)  # Tasks get 33%
        
        # Task table
        taskPanel = JPanel(BorderLayout())
        taskPanel.setBorder(BorderFactory.createTitledBorder("Active Tasks"))
        
        self.taskTableModel = DefaultTableModel()
        self.taskTableModel.addColumn("Timestamp")
        self.taskTableModel.addColumn("Type")
        self.taskTableModel.addColumn("URL")
        self.taskTableModel.addColumn("Status")
        self.taskTableModel.addColumn("Duration")
        
        self.taskTable = JTable(self.taskTableModel)
        self.taskTable.setAutoCreateRowSorter(True)
        self.taskTable.getColumnModel().getColumn(0).setPreferredWidth(150)
        self.taskTable.getColumnModel().getColumn(1).setPreferredWidth(120)
        self.taskTable.getColumnModel().getColumn(2).setPreferredWidth(300)
        self.taskTable.getColumnModel().getColumn(3).setPreferredWidth(130)
        self.taskTable.getColumnModel().getColumn(4).setPreferredWidth(80)
        
        # Color renderer for status
        statusRenderer = StatusCellRenderer()
        self.taskTable.getColumnModel().getColumn(3).setCellRenderer(statusRenderer)
        
        taskScrollPane = JScrollPane(self.taskTable)
        taskPanel.add(taskScrollPane, BorderLayout.CENTER)
        
        splitPane.setTopComponent(taskPanel)
        
        # Findings Panel
        findingsPanel = JPanel(BorderLayout())
        findingsPanel.setBorder(BorderFactory.createTitledBorder("Findings"))
        
        # Findings stats
        findingsStatsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.findingsStatsLabel = JLabel("Total: 0 | High: 0 | Medium: 0 | Low: 0 | Info: 0")
        self.findingsStatsLabel.setFont(Font("Monospaced", Font.BOLD, 11))
        findingsStatsPanel.add(self.findingsStatsLabel)
        findingsPanel.add(findingsStatsPanel, BorderLayout.NORTH)
        
        self.findingsTableModel = DefaultTableModel()
        self.findingsTableModel.addColumn("Discovered At")
        self.findingsTableModel.addColumn("URL")
        self.findingsTableModel.addColumn("Finding")
        self.findingsTableModel.addColumn("Severity")
        self.findingsTableModel.addColumn("Confidence")
        
        self.findingsTable = JTable(self.findingsTableModel)
        self.findingsTable.setAutoCreateRowSorter(True)
        self.findingsTable.getColumnModel().getColumn(0).setPreferredWidth(150)
        self.findingsTable.getColumnModel().getColumn(1).setPreferredWidth(300)
        self.findingsTable.getColumnModel().getColumn(2).setPreferredWidth(250)
        self.findingsTable.getColumnModel().getColumn(3).setPreferredWidth(80)
        self.findingsTable.getColumnModel().getColumn(4).setPreferredWidth(90)
        
        # Color renderers
        severityRenderer = SeverityCellRenderer()
        confidenceRenderer = ConfidenceCellRenderer()
        
        self.findingsTable.getColumnModel().getColumn(3).setCellRenderer(severityRenderer)
        self.findingsTable.getColumnModel().getColumn(4).setCellRenderer(confidenceRenderer)
        
        findingsScrollPane = JScrollPane(self.findingsTable)
        findingsPanel.add(findingsScrollPane, BorderLayout.CENTER)
        
        # Create nested split pane for Findings and Console - equal sizing
        bottomSplitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        bottomSplitPane.setResizeWeight(0.50)  # Findings and Console split 50/50 of bottom 66%
        bottomSplitPane.setTopComponent(findingsPanel)
        
        # Console Panel
        consolePanel = JPanel(BorderLayout())
        consolePanel.setBorder(BorderFactory.createTitledBorder("Console"))
        
        self.consoleTextArea = JTextArea()
        self.consoleTextArea.setEditable(False)
        self.consoleTextArea.setFont(Font("Monospaced", Font.PLAIN, 13))
        self.consoleTextArea.setLineWrap(True)
        self.consoleTextArea.setWrapStyleWord(False)

        # Apply theme colors
        self.applyConsoleTheme()
        
        consoleScrollPane = JScrollPane(self.consoleTextArea)
        consoleScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        
        self.console_user_scrolled = False
        
        from java.awt.event import AdjustmentListener
        class ScrollListener(AdjustmentListener):
            def __init__(self, extender):
                self.extender = extender
                self.last_value = 0
            
            def adjustmentValueChanged(self, e):
                scrollbar = e.getAdjustable()
                current_value = scrollbar.getValue()
                max_value = scrollbar.getMaximum() - scrollbar.getVisibleAmount()
                
                if current_value < max_value - 10:
                    self.extender.console_user_scrolled = True
                else:
                    self.extender.console_user_scrolled = False
        
        consoleScrollPane.getVerticalScrollBar().addAdjustmentListener(ScrollListener(self))
        
        consolePanel.add(consoleScrollPane, BorderLayout.CENTER)
        
        bottomSplitPane.setBottomComponent(consolePanel)
        
        splitPane.setBottomComponent(bottomSplitPane)

        self.panel.add(splitPane, BorderLayout.CENTER)

        # Store references for divider positioning
        self.mainSplitPane = splitPane
        self.bottomSplitPane = bottomSplitPane

        # Add component listener to set equal 33% splits when panel is shown
        from java.awt.event import ComponentAdapter
        class SplitPaneInitializer(ComponentAdapter):
            def __init__(self, extender):
                self.extender = extender
                self.initialized = False

            def componentResized(self, e):
                if not self.initialized and self.extender.panel.getHeight() > 0:
                    self.initialized = True
                    # Calculate 33% splits based on actual panel height
                    total_height = self.extender.panel.getHeight()
                    third = total_height / 3

                    # Set main split: Tasks gets top 33%
                    self.extender.mainSplitPane.setDividerLocation(int(third))

                    # Set bottom split: Findings and Console each get 50% of remaining 66%
                    # This means each gets 33% of total
                    self.extender.bottomSplitPane.setDividerLocation(int(third))

        self.panel.addComponentListener(SplitPaneInitializer(self))

    def applyConsoleTheme(self):
        """Apply theme colors to console"""
        if self.THEME == "Dark":
            # Dark theme: Charcoal background with light grey text
            self.consoleTextArea.setBackground(Color(0x32, 0x33, 0x34))  # #323334
            self.consoleTextArea.setForeground(Color(0x7D, 0xA3, 0x58))  # #7DA358
        else:
            # Light theme (default): White background with charcoal text
            self.consoleTextArea.setBackground(Color.WHITE)
            self.consoleTextArea.setForeground(Color(0x36, 0x45, 0x4F))  # Charcoal #36454F

    def refreshUI(self, event=None):
        # Skip if a refresh is already queued on the EDT
        if self._refresh_pending:
            return
        # Skip if nothing changed since last refresh
        if not self._ui_dirty:
            return

        class RefreshRunnable(Runnable):
            def __init__(self, extender):
                self.extender = extender

            def run(self):
                try:
                    # --- Copy data out of locks (fast) ---
                    with self.extender.stats_lock:
                        stats_snapshot = dict(self.extender.stats)

                    with self.extender.tasks_lock:
                        tasks_snapshot = []
                        for task in self.extender.tasks[-100:]:
                            duration = ""
                            if task.get("end_time"):
                                duration = "%.2fs" % (task["end_time"] - task["start_time"])
                            elif task.get("start_time"):
                                duration = "%.2fs" % (time.time() - task["start_time"])
                            tasks_snapshot.append([
                                task.get("timestamp", ""),
                                task.get("type", ""),
                                task.get("url", "")[:100],
                                task.get("status", ""),
                                duration
                            ])

                    with self.extender.findings_lock_ui:
                        findings_snapshot = []
                        severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Information": 0}
                        total_findings = 0
                        for finding in self.extender.findings_list:
                            total_findings += 1
                            severity = finding.get("severity", "Information")
                            if severity in severity_counts:
                                severity_counts[severity] += 1
                            findings_snapshot.append([
                                finding.get("discovered_at", ""),
                                finding.get("url", "")[:100],
                                finding.get("title", "")[:50],
                                severity,
                                finding.get("confidence", "")
                            ])

                    with self.extender.console_lock:
                        current_len = len(self.extender.console_messages)
                        prev_len = self.extender._last_console_len
                        if current_len != prev_len:
                            new_messages = list(self.extender.console_messages[prev_len:])
                            console_changed = True
                        else:
                            new_messages = []
                            console_changed = False
                        # Handle case where messages were trimmed (list shortened)
                        if current_len < prev_len:
                            console_changed = True
                            new_messages = list(self.extender.console_messages)
                            prev_len = 0

                    # --- Update Swing components (no locks held) ---

                    # Stats
                    for key, label in self.extender.statsLabels.items():
                        label.setText(str(stats_snapshot.get(key, 0)))

                    # Runtime status
                    self.extender.providerStatusLabel.setText(self.extender.AI_PROVIDER)
                    self.extender.modelStatusLabel.setText(self.extender.MODEL)
                    self.extender.scanStatusLabel.setText(
                        "Enabled" if self.extender.PASSIVE_SCANNING_ENABLED else "Disabled"
                    )
                    with self.extender.vuln_cache_lock:
                        self.extender.cacheStatusLabel.setText(str(len(self.extender.vuln_cache)))

                    # Task table — differential update (only change modified cells)
                    self.extender.update_table_diff(self.extender.taskTableModel, tasks_snapshot)

                    # Findings table — differential update (only change modified cells)
                    self.extender.update_table_diff(self.extender.findingsTableModel, findings_snapshot)

                    self.extender.findingsStatsLabel.setText(
                        "Total: %d | High: %d | Medium: %d | Low: %d | Info: %d" %
                        (total_findings, severity_counts["High"], severity_counts["Medium"],
                         severity_counts["Low"], severity_counts["Information"])
                    )

                    # Console — incremental append
                    if console_changed:
                        if prev_len == 0:
                            # Full rebuild (first load or after trim)
                            console_text = "\n".join(new_messages)
                            self.extender.consoleTextArea.setText(console_text)
                        else:
                            # Append only new messages
                            doc = self.extender.consoleTextArea.getDocument()
                            append_text = "\n" + "\n".join(new_messages)
                            doc.insertString(doc.getLength(), append_text, None)

                        self.extender._last_console_len = current_len

                        was_scrolled = self.extender.console_user_scrolled
                        if not was_scrolled:
                            try:
                                doc = self.extender.consoleTextArea.getDocument()
                                self.extender.consoleTextArea.setCaretPosition(doc.getLength())
                            except:
                                pass

                finally:
                    self.extender._refresh_pending = False

        self._ui_dirty = False
        self._refresh_pending = True
        
        # Async flush cache if dirty (non-blocking write-behind)
        self._async_save_cache()
        
        SwingUtilities.invokeLater(RefreshRunnable(self))

    def start_auto_refresh_timer(self):
        """Auto-refresh UI and check for stuck tasks"""
        def refresh_timer():
            check_interval = 0
            while True:
                time.sleep(5)
                self.refreshUI()
                
                # Check for stuck tasks periodically (every ~30 seconds)
                check_interval += 1
                if check_interval >= 6:
                    check_interval = 0
                    self.check_stuck_tasks()
        
        timer_thread = threading.Thread(target=refresh_timer)
        timer_thread.setDaemon(True)
        timer_thread.start()
    
    def check_stuck_tasks(self):
        """Automatically check for stuck tasks and log warnings"""
        current_time = time.time()
        stuck_found = False
        
        with self.tasks_lock:
            for idx, task in enumerate(self.tasks):
                status = task.get("status", "")
                start_time = task.get("start_time", 0)
                
                # Check if task has been analyzing for >5 minutes
                if ("Analyzing" in status or "Waiting" in status) and start_time > 0:
                    duration = current_time - start_time
                    
                    if duration > 300:  # 5 minutes
                        if not stuck_found:
                            self.stderr.println("\n[AUTO-CHECK] WARNING: STUCK TASK DETECTED")
                            stuck_found = True
                        
                        task_type = task.get("type", "Unknown")
                        url = task.get("url", "Unknown")[:50]
                        self.stderr.println("[AUTO-CHECK] Task %d stuck: %s | %.1f min | %s" % 
                                          (idx, task_type, duration/60, url))
        
        if stuck_found:
            self.stderr.println("[AUTO-CHECK] Run 'Debug Tasks' button for detailed diagnostics")
            self.stderr.println("[AUTO-CHECK] Or click 'Cancel All Tasks' to clear stuck tasks")
    
    def clearCompleted(self, event):
        with self.tasks_lock:
            self.tasks = [t for t in self.tasks if not (
                t.get("status") == "Completed" or 
                "Skipped" in t.get("status", "") or 
                "Error" in t.get("status", "")
            )]
        self.refreshUI()
    
    def cancelAllTasks(self, event):
        """Cancel all running/queued tasks (kill switch)"""
        self.stdout.println("\n[CANCEL ALL] Cancelling all active tasks...")
        
        cancelled_count = 0
        with self.tasks_lock:
            for task in self.tasks:
                status = task.get("status", "")
                # Cancel anything that's not already done
                if "Completed" not in status and "Error" not in status and "Cancelled" not in status:
                    task["status"] = "Cancelled"
                    task["end_time"] = time.time()
                    cancelled_count += 1
        
        self.stdout.println("[CANCEL ALL] Cancelled %d tasks" % cancelled_count)
        self.refreshUI()
    
    def pauseAllTasks(self, event):
        """Pause/Resume all running tasks"""
        # Check if any tasks are currently paused to determine toggle direction
        paused_count = 0
        active_count = 0
        
        with self.tasks_lock:
            for task in self.tasks:
                status = task.get("status", "")
                if "Paused" in status:
                    paused_count += 1
                elif "Analyzing" in status or "Queued" in status or "Waiting" in status:
                    active_count += 1
        
        # If more tasks are active than paused, pause all. Otherwise, resume all.
        if active_count > paused_count:
            # Pause all active tasks
            self.stdout.println("\n[PAUSE ALL] Pausing all active tasks...")
            with self.tasks_lock:
                for task in self.tasks:
                    status = task.get("status", "")
                    if "Analyzing" in status or "Queued" in status or "Waiting" in status:
                        task["status"] = "Paused"
            self.stdout.println("[PAUSE ALL] All tasks paused")
        else:
            # Resume all paused tasks
            self.stdout.println("\n[RESUME ALL] Resuming all paused tasks...")
            with self.tasks_lock:
                for task in self.tasks:
                    status = task.get("status", "")
                    if "Paused" in status:
                        task["status"] = "Analyzing"
            self.stdout.println("[RESUME ALL] All tasks resumed")
        
        self.refreshUI()
    
    def debugTasks(self, event):
        """Debug stuck/stalled tasks - provides detailed diagnostic information"""
        self.stdout.println("\n" + "="*60)
        self.stdout.println("[DEBUG] Task Status Diagnostic Report")
        self.stdout.println("="*60)
        
        current_time = time.time()
        
        with self.tasks_lock:
            total_tasks = len(self.tasks)
            active_tasks = []
            queued_tasks = []
            stuck_tasks = []
            
            for idx, task in enumerate(self.tasks):
                status = task.get("status", "Unknown")
                task_type = task.get("type", "Unknown")
                url = task.get("url", "Unknown")[:50]
                start_time = task.get("start_time", 0)
                
                # Calculate duration
                if start_time > 0:
                    duration = current_time - start_time
                else:
                    duration = 0
                
                # Categorize tasks
                if "Analyzing" in status or "Waiting" in status:
                    active_tasks.append((idx, task_type, status, duration, url))
                    
                    # Check if stuck (analyzing for >5 minutes)
                    if duration > 300:  # 5 minutes
                        stuck_tasks.append((idx, task_type, status, duration, url))
                
                elif "Queued" in status:
                    queued_tasks.append((idx, task_type, status, duration, url))
            
            # Print summary
            self.stdout.println("\n[DEBUG] Summary:")
            self.stdout.println("  Total Tasks: %d" % total_tasks)
            self.stdout.println("  Active (Analyzing/Waiting): %d" % len(active_tasks))
            self.stdout.println("  Queued: %d" % len(queued_tasks))
            self.stdout.println("  Stuck (>5 min): %d" % len(stuck_tasks))
            
            # Print active tasks
            if active_tasks:
                self.stdout.println("\n[DEBUG] Active Tasks:")
                for idx, task_type, status, duration, url in active_tasks[:10]:  # Show first 10
                    self.stdout.println("  [%d] %s | %s | %.1fs | %s" % 
                                      (idx, task_type, status, duration, url))
            
            # Print queued tasks
            if queued_tasks:
                self.stdout.println("\n[DEBUG] Queued Tasks:")
                for idx, task_type, status, duration, url in queued_tasks[:10]:
                    self.stdout.println("  [%d] %s | %s | %.1fs | %s" % 
                                      (idx, task_type, status, duration, url))
            
            # Print stuck tasks with detailed diagnostics
            if stuck_tasks:
                self.stdout.println("\n[DEBUG] WARNING: STUCK TASKS DETECTED:")
                for idx, task_type, status, duration, url in stuck_tasks:
                    self.stdout.println("  [%d] %s | %s | %.1f minutes | %s" % 
                                      (idx, task_type, status, duration/60, url))
                
                self.stdout.println("\n[DEBUG] Possible causes:")
                self.stdout.println("  1. AI request timeout (increase in Settings)")
                self.stdout.println("  2. Network issues (check connectivity)")
                self.stdout.println("  3. AI provider unavailable (test connection)")
                self.stdout.println("  4. Thread deadlock (restart Burp Suite)")
                self.stdout.println("\n[DEBUG] Recommended actions:")
                self.stdout.println("  - Click 'Cancel All Tasks' to clear stuck tasks")
                self.stdout.println("  - Check AI connection: Settings → Test Connection")
                self.stdout.println("  - Increase timeout: Settings → Advanced → AI Request Timeout")
                self.stdout.println("  - Check Console for error messages")
            
            # Check semaphore status
            self.stdout.println("\n[DEBUG] Threading Status:")
            self.stdout.println("  Rate Limit Delay: %.1fs" % self.min_delay)
            self.stdout.println("  Last Request: %.1fs ago" % (current_time - self.last_request_time))
            
            # Check if semaphore might be blocked
            if len(active_tasks) > 0 and len(queued_tasks) > 5:
                self.stdout.println("\n[DEBUG] Warning: Many queued tasks with active task")
                self.stdout.println("  This is normal - tasks are rate-limited to prevent API overload")
                self.stdout.println("  Current rate: 1 task every %.1f seconds" % self.min_delay)
        
        self.stdout.println("\n" + "="*60)
        self.stdout.println("[DEBUG] End of diagnostic report")
        self.stdout.println("="*60)
        
        self.refreshUI()
    
    def load_config(self):
        """Load configuration from disk"""
        try:
            import os
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                
                # Check config version and migrate if needed
                config_version = config.get("config_version", 1)
                if config_version < self.CONFIG_VERSION:
                    self.stdout.println("[CONFIG] Migrating config from v%d to v%d" % (config_version, self.CONFIG_VERSION))
                    config = self._migrate_config(config, config_version)
                
                # Load settings
                self.AI_PROVIDER = config.get("ai_provider", self.AI_PROVIDER)
                self.API_URL = config.get("api_url", self.API_URL)
                self.API_KEY = config.get("api_key", self.API_KEY)
                self.MODEL = config.get("model", self.MODEL)
                self.AZURE_API_VERSION = config.get("azure_api_version", self.AZURE_API_VERSION)
                self.MAX_TOKENS = config.get("max_tokens", self.MAX_TOKENS)
                self.AI_REQUEST_TIMEOUT = config.get("ai_request_timeout", self.AI_REQUEST_TIMEOUT)
                self.VERBOSE = config.get("verbose", self.VERBOSE)
                saved_theme = config.get("theme", self.THEME)
                self.THEME = saved_theme if saved_theme in ("Light", "Dark") else "Light"
                self.PASSIVE_SCANNING_ENABLED = config.get("passive_scanning_enabled", self.PASSIVE_SCANNING_ENABLED)

                self.stdout.println("\n[CONFIG] Loaded saved configuration from %s" % self.config_file)
                self.stdout.println("[CONFIG] Provider: %s | Model: %s" % (self.AI_PROVIDER, self.MODEL))
            else:
                self.stdout.println("\n[CONFIG] No saved configuration found - using defaults")
                self.stdout.println("[CONFIG] Config will be saved to: %s" % self.config_file)
        except Exception as e:
            self.stderr.println("[!] Failed to load config: %s" % e)
            self.stderr.println("[!] Using default settings")

    def _migrate_config(self, old_config, from_version):
        """Migrate config from old format to new."""
        # v1 -> v2: No breaking changes in this release, just add version number
        old_config["config_version"] = self.CONFIG_VERSION
        # Don't call save_config() here — stdout not ready yet during initial load
        # Migration will auto-persist when user saves settings
        return old_config

    def load_vuln_cache(self):
        """Load persistent vulnerability cache from disk."""
        try:
            import os
            if not os.path.exists(self.vuln_cache_file):
                self.stdout.println("[CACHE] No persistent vulnerability cache found")
                return

            with open(self.vuln_cache_file, 'r') as f:
                payload = json.load(f)

            entries = payload.get("entries", {}) if isinstance(payload, dict) else {}
            if not isinstance(entries, dict):
                entries = {}

            with self.vuln_cache_lock:
                self.vuln_cache = entries

            self.stdout.println("[CACHE] Loaded %d cached request signature(s)" % len(entries))
            self._ui_dirty = True
        except Exception as e:
            self.stderr.println("[!] Failed to load vulnerability cache: %s" % e)

    def save_vuln_cache(self):
        """Persist vulnerability cache to disk."""
        try:
            with self.vuln_cache_lock:
                cache_snapshot = dict(self.vuln_cache)
            payload = {
                "version": self.VERSION,
                "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "entries": cache_snapshot
            }
            with open(self.vuln_cache_file, 'w') as f:
                json.dump(payload, f, indent=2)
            return True
        except Exception as e:
            self.stderr.println("[!] Failed to save vulnerability cache: %s" % e)
            return False

    def _async_save_cache(self):
        """Non-blocking background write if cache is dirty. Prevents race conditions during shutdown."""
        if not self._cache_dirty:
            return
        
        self._cache_dirty = False  # Optimistic clear before spawn
        
        def background_save():
            try:
                self.save_vuln_cache()
            except Exception as e:
                # Re-queue on failure so we retry on next timer tick
                self._cache_dirty = True
                self.stderr.println("[!] Background cache save failed: %s" % e)
        
        t = threading.Thread(target=background_save)
        t.setDaemon(True)
        t.start()

    def _get_request_signature(self, data):
        """Build a stable request signature for persistent cache matching."""
        base_url = str(data.get("url", "")).split('?', 1)[0]
        param_names = sorted([p.get("name", "") for p in data.get("params_sample", []) if p.get("name")])

        req_header_names = []
        for header in data.get("request_headers", [])[:10]:
            req_header_names.append(str(header).split(':', 1)[0].strip().lower())

        res_header_names = []
        for header in data.get("response_headers", [])[:10]:
            res_header_names.append(str(header).split(':', 1)[0].strip().lower())

        # Check auth presence (authorization, cookie, api-key headers)
        auth_present = any(
            h.lower().startswith(('authorization:', 'cookie:', 'x-api-key:'))
            for h in data.get("request_headers", [])
        )
        auth_length = sum(
            len(h) for h in data.get("request_headers", [])
            if h.lower().startswith(('authorization:', 'cookie:', 'x-api-key:'))
        )

        signature_obj = {
            "provider": self.AI_PROVIDER,
            "model": self.MODEL,
            "method": data.get("method", ""),
            "url": base_url,
            "status": data.get("status", 0),
            "mime_type": data.get("mime_type", ""),
            "param_names": param_names,
            "request_headers": sorted(req_header_names),
            "response_headers": sorted(res_header_names),
            "auth_present": auth_present,
            "auth_length": auth_length
        }
        encoded = json.dumps(signature_obj, sort_keys=True)
        # Use SHA-256 instead of MD5 for better cryptographic security
        return hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:32]

    def _get_cached_findings_for_signature(self, signature):
        with self.vuln_cache_lock:
            entry = self.vuln_cache.get(signature)
            if not entry:
                return None

            # Track usage for observability
            entry["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            entry["hit_count"] = int(entry.get("hit_count", 0)) + 1

            findings = entry.get("findings", [])
            if not isinstance(findings, list):
                findings = []
        
        # Set dirty flag for async write-behind (don't block on disk I/O)
        self._cache_dirty = True
        return findings

    def _store_cached_findings(self, signature, url, findings):
        """Store normalized findings for future cache hits."""
        if isinstance(findings, dict):
            findings = [findings]

        normalized = []
        for item in findings:
            if not isinstance(item, dict):
                continue
            normalized.append({
                "title": item.get("title", "AI Finding"),
                "severity": item.get("severity", "information"),
                "confidence": item.get("confidence", 50),
                "detail": item.get("detail", ""),
                "cwe": item.get("cwe", ""),
                "owasp": item.get("owasp", ""),
                "remediation": item.get("remediation", "")
            })

        if not normalized:
            return

        with self.vuln_cache_lock:
            self.vuln_cache[signature] = {
                "url": str(url).split('?', 1)[0],
                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "hit_count": 0,
                "findings": normalized
            }

        # Set dirty flag for async write-behind (don't block analysis thread on disk I/O)
        self._cache_dirty = True
        self._ui_dirty = True
    
    def save_config(self):
        """Save configuration to disk"""
        try:
            config = {
                "config_version": self.CONFIG_VERSION,
                "ai_provider": self.AI_PROVIDER,
                "api_url": self.API_URL,
                "api_key": self.API_KEY,
                "model": self.MODEL,
                "azure_api_version": self.AZURE_API_VERSION,
                "max_tokens": self.MAX_TOKENS,
                "ai_request_timeout": self.AI_REQUEST_TIMEOUT,
                "verbose": self.VERBOSE,
                "theme": self.THEME,
                "passive_scanning_enabled": self.PASSIVE_SCANNING_ENABLED,
                "version": self.VERSION,
                "last_saved": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            self.stdout.println("[CONFIG] Configuration saved to %s" % self.config_file)
            return True
        except Exception as e:
            self.stderr.println("[!] Failed to save config: %s" % e)
            return False

    def apply_environment_config(self):
        """Apply optional environment-variable overrides for cloud provider setup."""
        try:
            import os
            env_values = dict(os.environ)

            # Merge .env values only for keys not already set in process environment.
            dotenv_values = self._load_dotenv_values()
            for key, value in dotenv_values.items():
                if key not in env_values or not env_values.get(key, "").strip():
                    env_values[key] = value

            azure_endpoint = env_values.get("AZURE_OPENAI_ENDPOINT", "").strip()
            azure_api_key = env_values.get("AZURE_OPENAI_API_KEY", "").strip()
            azure_deployment = env_values.get("AZURE_OPENAI_DEPLOYMENT", "").strip()
            azure_model = env_values.get("AZURE_OPENAI_MODEL", "").strip()
            azure_api_version = env_values.get("OPENAI_API_VERSION", "").strip()
            if not azure_api_version:
                azure_api_version = env_values.get("AZURE_OPENAI_API_VERSION", "").strip()

            if azure_api_version:
                self.AZURE_API_VERSION = azure_api_version
                self.stdout.println("[CONFIG] Azure API version set to %s" % self.AZURE_API_VERSION)

            if azure_endpoint and azure_api_key:
                # Prefer explicit saved provider unless it is still the default local Ollama setup.
                if self.AI_PROVIDER == "Ollama" or not self.API_KEY:
                    self.AI_PROVIDER = "Azure Foundry"
                    self.API_URL = azure_endpoint
                    self.API_KEY = azure_api_key

                    if azure_deployment:
                        self.MODEL = azure_deployment
                    elif azure_model:
                        self.MODEL = azure_model

                    self.stdout.println("[CONFIG] Applied Azure Foundry settings from environment variables")
                    if not (azure_deployment or azure_model):
                        self.stdout.println("[CONFIG] Tip: set AZURE_OPENAI_DEPLOYMENT to auto-fill Model")
        except Exception as e:
            self.stderr.println("[!] Failed to apply environment config: %s" % e)

    def _load_dotenv_values(self):
        """Load key/value pairs from a nearby .env file if present."""
        values = {}
        try:
            import os
            candidate_paths = []

            try:
                candidate_paths.append(os.path.join(os.getcwd(), ".env"))
            except:
                pass

            try:
                if '__file__' in globals() and __file__:
                    candidate_paths.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
            except:
                pass

            # Optional user-level fallback.
            candidate_paths.append(os.path.join(os.path.expanduser("~"), ".silentchain.env"))

            loaded_path = None
            for path in candidate_paths:
                if path and os.path.isfile(path):
                    loaded_path = path
                    break

            if not loaded_path:
                return values

            with open(loaded_path, 'r') as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line or line.startswith('#') or '=' not in line:
                        continue

                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()

                    # Support optional 'export KEY=value' style.
                    if key.startswith('export '):
                        key = key[len('export '):].strip()

                    if not key:
                        continue

                    # Strip surrounding quotes when present.
                    if ((value.startswith('"') and value.endswith('"')) or
                        (value.startswith("'") and value.endswith("'"))):
                        value = value[1:-1]

                    values[key] = value

            self.stdout.println("[CONFIG] Loaded environment overrides from %s" % loaded_path)
            return values
        except Exception as e:
            self.stderr.println("[!] Failed to read .env file: %s" % e)
            return values
    
    def toggleScanning(self, event):
        """Toggle passive scanning on/off"""
        self.PASSIVE_SCANNING_ENABLED = not self.PASSIVE_SCANNING_ENABLED
        self._sync_scanning_button()

        if self.PASSIVE_SCANNING_ENABLED:
            self.stdout.println("\n[SCANNING] ENABLED - Passive scanning is now ON")
        else:
            self.stdout.println("\n[SCANNING] DISABLED - Passive scanning is now OFF")

        if not self.save_config():
            self.stderr.println("[!] Failed to save config")
        self.refreshUI()

    def _sync_scanning_button(self):
        """Keep scan toggle label/color in sync with runtime state."""
        if not hasattr(self, 'scanningButton'):
            return
        if self.PASSIVE_SCANNING_ENABLED:
            self.scanningButton.setText("Stop Scanning")
            self.scanningButton.setBackground(Color(0x2E, 0xCC, 0x71))
        else:
            self.scanningButton.setText("Start Scanning")
            self.scanningButton.setBackground(Color(0xE7, 0x4C, 0x3C))
        self.scanningButton.setForeground(Color.WHITE)
        self.scanningButton.setOpaque(True)
    
    def exportFindings(self, event):
        """Export findings to CSV file"""
        if self.findingsTableModel.getRowCount() == 0:
            self.stdout.println("\n[EXPORT] No findings to export")
            return
        
        try:
            import time
            from javax.swing import JFileChooser
            from java.io import File
            
            # Create file chooser
            fileChooser = JFileChooser()
            
            # Set default filename with timestamp
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            fileChooser.setSelectedFile(File("SILENTCHAIN_Findings_%s.csv" % timestamp))
            
            result = fileChooser.showSaveDialog(self.panel)
            
            if result == JFileChooser.APPROVE_OPTION:
                filepath = str(fileChooser.getSelectedFile().getAbsolutePath())
                
                # Write CSV
                with open(filepath, 'w') as f:
                    # Write header
                    headers = []
                    for col in range(self.findingsTableModel.getColumnCount()):
                        headers.append(self.findingsTableModel.getColumnName(col))
                    f.write(','.join(['"' + h + '"' for h in headers]) + '\n')
                    
                    # Write data rows
                    for row in range(self.findingsTableModel.getRowCount()):
                        values = []
                        for col in range(self.findingsTableModel.getColumnCount()):
                            val = str(self.findingsTableModel.getValueAt(row, col))
                            # Escape quotes
                            val = val.replace('"', '""')
                            values.append('"' + val + '"')
                        f.write(','.join(values) + '\n')
                
                self.stdout.println("\n[EXPORT] OK Findings exported to: %s" % filepath)
                self.stdout.println("[EXPORT] Total findings: %d" % self.findingsTableModel.getRowCount())
        except Exception as e:
            self.stderr.println("[!] Export failed: %s" % e)

    def openUpdatesPage(self, event):
        """Open updates page in browser"""
        self.stdout.println("\n[UPDATE] Checking for updates...")
    
    def openSettings(self, event):
        """Open settings dialog with AI provider and advanced configuration"""
        from javax.swing import JDialog, JTabbedPane, JTextField, JComboBox, JPasswordField, JTextArea
        from javax.swing import SwingConstants, JCheckBox
        from java.awt import GridBagLayout, GridBagConstraints, Insets
        
        # Debug: Log that settings is opening
        self.stdout.println("\n[SETTINGS] Opening configuration dialog...")
        self.stdout.println("[SETTINGS] Current Provider: %s" % self.AI_PROVIDER)
        self.stdout.println("[SETTINGS] Current Model: %s" % self.MODEL)
        
        dialog = JDialog()
        dialog.setTitle("SILENTCHAIN Settings - Community Edition")
        dialog.setModal(True)
        dialog.setSize(750, 650)  # Wider to accommodate long model names, taller for Advanced tab
        dialog.setLocationRelativeTo(None)
        
        tabbedPane = JTabbedPane()
        
        # AI PROVIDER TAB
        aiPanel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.HORIZONTAL
        
        row = 0
        
        gbc.gridx = 0
        gbc.gridy = row
        aiPanel.add(JLabel("AI Provider:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        providerCombo = JComboBox(["Ollama", "OpenAI", "Claude", "Gemini", "Azure Foundry"])
        providerCombo.setSelectedItem(self.AI_PROVIDER)
        
        # Auto-update API URL when provider changes
        from java.awt.event import ActionListener
        class ProviderChangeListener(ActionListener):
            def __init__(self, urlField):
                self.urlField = urlField
            
            def actionPerformed(self, e):
                provider = str(e.getSource().getSelectedItem())
                # Default URLs for each provider
                default_urls = {
                    "Ollama": "http://localhost:11434",
                    "OpenAI": "https://api.openai.com/v1",
                    "Claude": "https://api.anthropic.com/v1",
                    "Gemini": "https://generativelanguage.googleapis.com/v1",
                    "Azure Foundry": "https://YOUR-RESOURCE.openai.azure.com"
                }
                if provider in default_urls:
                    self.urlField.setText(default_urls[provider])
        
        aiPanel.add(providerCombo, gbc)
        gbc.gridwidth = 1
        row += 1
        
        gbc.gridx = 0
        gbc.gridy = row
        aiPanel.add(JLabel("API URL:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        apiUrlField = JTextField(self.API_URL, 30)
        
        # Add listener AFTER creating the field
        providerCombo.addActionListener(ProviderChangeListener(apiUrlField))
        
        aiPanel.add(apiUrlField, gbc)
        gbc.gridwidth = 1
        row += 1
        
        gbc.gridx = 0
        gbc.gridy = row
        aiPanel.add(JLabel("API Key:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        apiKeyField = JPasswordField(self.API_KEY, 30)
        aiPanel.add(apiKeyField, gbc)
        gbc.gridwidth = 1
        row += 1
        
        gbc.gridx = 0
        gbc.gridy = row
        aiPanel.add(JLabel("Model:"), gbc)
        gbc.gridx = 1
        models_to_show = self.available_models if self.available_models else [self.MODEL]
        modelCombo = JComboBox(models_to_show)
        if self.MODEL in models_to_show:
            modelCombo.setSelectedItem(self.MODEL)
        aiPanel.add(modelCombo, gbc)
        
        gbc.gridx = 2
        refreshModelsBtn = JButton("Refresh")
        
        def refreshModels(e):
            refreshModelsBtn.setEnabled(False)
            refreshModelsBtn.setText("...")
            self.stdout.println("[SETTINGS] Fetching models...")
            def _do_refresh():
                try:
                    if self.test_ai_connection():
                        def _update_ui():
                            modelCombo.removeAllItems()
                            for model in self.available_models:
                                modelCombo.addItem(model)
                            self.stdout.println("[SETTINGS] Models refreshed")
                            refreshModelsBtn.setEnabled(True)
                            refreshModelsBtn.setText("Refresh")
                        SwingUtilities.invokeLater(lambda: _update_ui())
                    else:
                        def _restore():
                            refreshModelsBtn.setEnabled(True)
                            refreshModelsBtn.setText("Refresh")
                        SwingUtilities.invokeLater(lambda: _restore())
                except:
                    def _restore():
                        refreshModelsBtn.setEnabled(True)
                        refreshModelsBtn.setText("Refresh")
                    SwingUtilities.invokeLater(lambda: _restore())
            t = threading.Thread(target=_do_refresh)
            t.setDaemon(True)
            t.start()

        refreshModelsBtn.addActionListener(refreshModels)
        aiPanel.add(refreshModelsBtn, gbc)
        row += 1
        
        gbc.gridx = 0
        gbc.gridy = row
        aiPanel.add(JLabel("Max Tokens:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        maxTokensField = JTextField(str(self.MAX_TOKENS), 10)
        aiPanel.add(maxTokensField, gbc)
        gbc.gridwidth = 1
        row += 1
        
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 3
        testBtn = JButton("Test Connection")
        
        def testConnection(e):
            testBtn.setEnabled(False)
            testBtn.setText("Testing...")
            old_provider = self.AI_PROVIDER
            old_url = self.API_URL
            old_key = self.API_KEY

            self.AI_PROVIDER = str(providerCombo.getSelectedItem())
            self.API_URL = apiUrlField.getText()
            self.API_KEY = "".join(apiKeyField.getPassword())

            def _do_test():
                try:
                    success = self.test_ai_connection()
                    if not success:
                        self.AI_PROVIDER = old_provider
                        self.API_URL = old_url
                        self.API_KEY = old_key
                finally:
                    def _restore():
                        testBtn.setEnabled(True)
                        testBtn.setText("Test Connection")
                    SwingUtilities.invokeLater(lambda: _restore())
            t = threading.Thread(target=_do_test)
            t.setDaemon(True)
            t.start()

        testBtn.addActionListener(testConnection)
        aiPanel.add(testBtn, gbc)
        row += 1
        
        gbc.gridy = row
        helpText = JTextArea(
            "Provider-specific URLs:\n\n"
            "Ollama: http://localhost:11434\n"
            "OpenAI: https://api.openai.com/v1\n"
            "Claude: https://api.anthropic.com/v1\n"
            "Gemini: https://generativelanguage.googleapis.com/v1\n"
            "Azure Foundry: https://YOUR-RESOURCE.openai.azure.com\n\n"
            "API Keys required for: OpenAI, Claude, Gemini, Azure Foundry\n"
            "For Azure Foundry, set Model to your deployment name"
        )
        helpText.setEditable(False)
        helpText.setBackground(aiPanel.getBackground())
        aiPanel.add(helpText, gbc)
        
        tabbedPane.addTab("AI Provider", aiPanel)
        
        # ADVANCED TAB
        advancedPanel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.HORIZONTAL
        
        row = 0

        # Passive Scanning toggle
        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Passive Scanning:"), gbc)
        gbc.gridx = 1
        passiveScanCheck = JCheckBox("Enable automatic scanning", self.PASSIVE_SCANNING_ENABLED)
        advancedPanel.add(passiveScanCheck, gbc)
        row += 1

        # Help text for passive scanning
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        passiveScanHelp = JTextArea(
            "When disabled, passive scanning is turned off but you can still\n"
            "manually analyze requests via right-click context menu."
        )
        passiveScanHelp.setEditable(False)
        passiveScanHelp.setBackground(advancedPanel.getBackground())
        passiveScanHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(passiveScanHelp, gbc)
        row += 1
        gbc.gridwidth = 1

        # Theme dropdown
        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Console Theme:"), gbc)
        gbc.gridx = 1
        themeCombo = JComboBox(["Light", "Dark"])
        themeCombo.setSelectedItem(self.THEME)
        advancedPanel.add(themeCombo, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Verbose Logging:"), gbc)
        gbc.gridx = 1
        verboseCheck = JCheckBox("", self.VERBOSE)
        advancedPanel.add(verboseCheck, gbc)
        row += 1

        # AI Request Timeout setting
        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("AI Request Timeout (seconds):"), gbc)
        gbc.gridx = 1
        timeoutField = JTextField(str(self.AI_REQUEST_TIMEOUT), 10)
        advancedPanel.add(timeoutField, gbc)
        row += 1
        
        # Help text for timeout
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        timeoutHelp = JTextArea(
            "Timeout for AI API requests (default: 60 seconds).\n"
            "Range: 10 to 99999 seconds (27.7 hours max).\n"
            "Increase if you get timeout errors.\n"
            "Recommended: 30-120s (fast models), 180-600s (large models)."
        )
        timeoutHelp.setEditable(False)
        timeoutHelp.setBackground(advancedPanel.getBackground())
        timeoutHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(timeoutHelp, gbc)
        row += 1
        gbc.gridwidth = 1
        
        # Debug Tasks button
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        debugTasksBtn = JButton("Run Task Diagnostics", actionPerformed=self.debugTasks)
        advancedPanel.add(debugTasksBtn, gbc)
        row += 1
        
        # Help text for debug
        gbc.gridy = row
        debugHelp = JTextArea(
            "Click to generate detailed diagnostic report for stuck/queued tasks.\n"
            "Shows task counts, durations, threading status, and recommendations."
        )
        debugHelp.setEditable(False)
        debugHelp.setBackground(advancedPanel.getBackground())
        debugHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(debugHelp, gbc)
        row += 1
        
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        editionNotice = JTextArea(
            "COMMUNITY EDITION - Passive Analysis Only\n\n"
            "This edition provides AI-powered passive security analysis."
        )
        editionNotice.setEditable(False)
        editionNotice.setBackground(advancedPanel.getBackground())
        editionNotice.setFont(Font("Dialog", Font.PLAIN, 11))
        advancedPanel.add(editionNotice, gbc)
        
        tabbedPane.addTab("Advanced", advancedPanel)
        
        # BUTTONS
        buttonPanel = JPanel()
        
        def saveSettings(e):
            # Save AI Provider settings
            self.AI_PROVIDER = str(providerCombo.getSelectedItem())
            self.API_URL = apiUrlField.getText()
            self.API_KEY = "".join(apiKeyField.getPassword())
            self.MODEL = str(modelCombo.getSelectedItem())
            try:
                self.MAX_TOKENS = int(maxTokensField.getText())
            except ValueError:
                self.MAX_TOKENS = 2048
                self.stderr.println("[!] Invalid Max Tokens value, using default: 2048")
            
            # Save Advanced settings
            self.PASSIVE_SCANNING_ENABLED = passiveScanCheck.isSelected()
            self._sync_scanning_button()
            self.THEME = str(themeCombo.getSelectedItem())
            self.VERBOSE = verboseCheck.isSelected()

            # Apply theme immediately
            self.applyConsoleTheme()

            # Save timeout setting
            try:
                timeout = int(timeoutField.getText())
                if timeout < 10:
                    self.AI_REQUEST_TIMEOUT = 10
                    self.stderr.println("[!] Timeout too low, using minimum: 10 seconds")
                elif timeout > 99999:
                    self.AI_REQUEST_TIMEOUT = 99999
                    self.stderr.println("[!] Timeout too high, using maximum: 99999 seconds")
                else:
                    self.AI_REQUEST_TIMEOUT = timeout
            except ValueError:
                self.AI_REQUEST_TIMEOUT = 60
                self.stderr.println("[!] Invalid timeout value, using default: 60 seconds")
            
            # Log confirmation
            self.stdout.println("\n[SETTINGS] OK Configuration saved successfully")
            self.stdout.println("[SETTINGS] AI Provider: %s" % self.AI_PROVIDER)
            self.stdout.println("[SETTINGS] API URL: %s" % self.API_URL)
            self.stdout.println("[SETTINGS] Model: %s" % self.MODEL)
            self.stdout.println("[SETTINGS] Max Tokens: %d" % int(self.MAX_TOKENS))
            self.stdout.println("[SETTINGS] Request Timeout: %d seconds" % int(self.AI_REQUEST_TIMEOUT))
            self.stdout.println("[SETTINGS] Console Theme: %s" % self.THEME)
            self.stdout.println("[SETTINGS] Verbose Logging: %s" % ("Enabled" if self.VERBOSE else "Disabled"))
            self.stdout.println("[SETTINGS] Passive Scanning: %s" % ("Enabled" if self.PASSIVE_SCANNING_ENABLED else "Disabled"))

            # Save configuration to disk
            if self.save_config():
                self.stdout.println("[SETTINGS] OK Configuration persisted to disk")
            
            dialog.dispose()
        
        saveBtn = JButton("Save")
        saveBtn.addActionListener(saveSettings)
        buttonPanel.add(saveBtn)
        
        cancelBtn = JButton("Cancel")
        cancelBtn.addActionListener(lambda e: dialog.dispose())
        buttonPanel.add(cancelBtn)
        
        # Assemble dialog
        dialog.add(tabbedPane, BorderLayout.CENTER)
        dialog.add(buttonPanel, BorderLayout.SOUTH)
        
        # Show dialog
        dialog.setVisible(True)

    def log_to_console(self, message):
        with self.console_lock:
            timestamp = datetime.now().strftime("%H:%M:%S")
            message_str = str(message)
            
            if "http://" in message_str or "https://" in message_str:
                import re
                def truncate_url(match):
                    url = match.group(0)
                    if len(url) > 100:
                        return url[:97] + "..."
                    return url
                
                message_str = re.sub(r'https?://[^\s]+', truncate_url, message_str)
            
            if len(message_str) > 150:
                message_str = message_str[:147] + "..."
            
            formatted_msg = "[%s] %s" % (timestamp, message_str)
            self.console_messages.append(formatted_msg)
            
            if len(self.console_messages) > self.max_console_messages:
                self.console_messages = self.console_messages[-self.max_console_messages:]
        self._ui_dirty = True

    def add_finding(self, url, title, severity, confidence):
        with self.findings_lock_ui:
            finding = {
                "discovered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "url": url,
                "title": title,
                "severity": severity,
                "confidence": confidence
            }
            self.findings_list.append(finding)
        self._ui_dirty = True
    
    def addTask(self, task_type, url, status="Queued", messageInfo=None):
        with self.tasks_lock:
            task = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": task_type,
                "url": url,
                "status": status,
                "start_time": time.time(),
                "messageInfo": messageInfo
            }
            self.tasks.append(task)
            with self.stats_lock:
                self.stats["total_requests"] += 1
            self._ui_dirty = True
            return len(self.tasks) - 1

    def updateTask(self, task_id, status, error=None):
        with self.tasks_lock:
            if task_id < len(self.tasks):
                self.tasks[task_id]["status"] = status
                self.tasks[task_id]["end_time"] = time.time()
                if error:
                    self.tasks[task_id]["error"] = error
        self._ui_dirty = True

    def updateStats(self, stat_key, increment=1):
        with self.stats_lock:
            self.stats[stat_key] = self.stats.get(stat_key, 0) + increment
        self._ui_dirty = True

    def getTabCaption(self):
        return "SILENTCHAIN"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        
        context = invocation.getInvocationContext()
        if context in [invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, 
                      invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
                      invocation.CONTEXT_PROXY_HISTORY,
                      invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
                      invocation.CONTEXT_TARGET_SITE_MAP_TREE]:
            
            messages = invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                analyze_item = JMenuItem("Analyze Request")
                analyze_item.addActionListener(lambda x: self.analyzeFromContextMenu(messages))
                menu_list.add(analyze_item)
        
        return menu_list if menu_list.size() > 0 else None

    def analyzeFromContextMenu(self, messages):
        t = threading.Thread(target=self._analyzeFromContextMenuThread, args=(messages,))
        t.setDaemon(True)
        t.start()
    
    def _analyzeFromContextMenuThread(self, messages):
        seen_keys = set()
        unique_messages = []
        
        for message in messages:
            try:
                req = self.helpers.analyzeRequest(message)
                url_str = str(req.getUrl())
                
                request_bytes = message.getRequest()
                if request_bytes:
                    import hashlib
                    # Use SHA-256 instead of MD5 for better hash quality
                    request_hash = hashlib.sha256(bytes(request_bytes.tostring())).hexdigest()[:8]
                    unique_key = "%s|%s" % (url_str, request_hash)
                else:
                    unique_key = url_str
                
                current_time = time.time()
                with self.context_menu_lock:
                    last_invoke_time = self.context_menu_last_invoke.get(unique_key, 0)
                    if current_time - last_invoke_time < self.context_menu_debounce_time:
                        if self.VERBOSE:
                            self.stdout.println("[DEBUG] Debouncing duplicate context menu invoke: %s" % url_str)
                        continue
                    
                    self.context_menu_last_invoke[unique_key] = current_time
                
                if unique_key not in seen_keys:
                    seen_keys.add(unique_key)
                    unique_messages.append(message)
            except:
                pass
        
        if len(unique_messages) == 0:
            return
        
        self.stdout.println("\n[CONTEXT MENU] Analyzing %d unique request(s)..." % len(unique_messages))
        for message in unique_messages:
            try:
                req = self.helpers.analyzeRequest(message)
                url_str = str(req.getUrl())
                self.stdout.println("[CONTEXT MENU] URL: %s" % url_str)
                
                if message.getResponse() is None:
                    self.stdout.println("[CONTEXT MENU] No response - sending request...")
                    
                    try:
                        http_service = message.getHttpService()
                        request_bytes = message.getRequest()
                        
                        response = self.callbacks.makeHttpRequest(http_service, request_bytes)
                        
                        if response is None or response.getResponse() is None:
                            self.stdout.println("[CONTEXT MENU] ERROR: Failed to get response")
                            continue
                        
                        message = response
                        
                    except Exception as e:
                        self.stderr.println("[!] Failed to send request: %s" % e)
                        continue
                
                self.stdout.println("[CONTEXT MENU] Running analysis...")
                task_id = self.addTask("CONTEXT", url_str, "Queued", message)
                # Use thread pool for forced analysis (context menu always forces analysis)
                task = ForcedAnalyzeTask(self, message, url_str, task_id)
                self.thread_pool.submit(task)
            except Exception as e:
                self.stderr.println("[!] Context menu error: %s" % e)

    def test_ai_connection(self):
        self.stdout.println("\n[AI CONNECTION] Testing connection to %s..." % self.API_URL)
        
        try:
            if self.AI_PROVIDER == "Ollama":
                return self._test_ollama_connection()
            elif self.AI_PROVIDER == "OpenAI":
                return self._test_openai_connection()
            elif self.AI_PROVIDER == "Claude":
                return self._test_claude_connection()
            elif self.AI_PROVIDER == "Gemini":
                return self._test_gemini_connection()
            elif self.AI_PROVIDER == "Azure Foundry":
                return self._test_azure_foundry_connection()
            else:
                self.stderr.println("[!] Unknown AI provider: %s" % self.AI_PROVIDER)
                return False
        except Exception as e:
            self.stderr.println("[!] AI connection test failed: %s" % e)
            return False
    
    def _test_ollama_connection(self):
        try:
            tags_url = self.API_URL.rstrip('/api/generate').rstrip('/') + "/api/tags"
            
            req = urllib2.Request(tags_url)
            req.add_header('Content-Type', 'application/json')
            
            response = urllib2.urlopen(req, timeout=10)
            data = json.loads(response.read())
            
            if 'models' in data:
                self.available_models = [model['name'] for model in data['models']]
                self.stdout.println("[AI CONNECTION] OK Connected to Ollama")
                self.stdout.println("[AI CONNECTION] Found %d models" % len(self.available_models))
                
                if self.MODEL not in self.available_models and len(self.available_models) > 0:
                    old_model = self.MODEL
                    self.MODEL = self.available_models[0]
                    self.stdout.println("[AI CONNECTION] Model '%s' not found, using '%s'" % 
                                      (old_model, self.MODEL))
                
                return True
            else:
                self.stderr.println("[!] Unexpected response from Ollama API")
                return False
                
        except urllib2.URLError as e:
            self.stderr.println("[!] Cannot connect to Ollama at %s: %s" % (self.API_URL, e))
            return False
    
    def _test_openai_connection(self):
        if not self.API_KEY:
            self.stderr.println("[!] OpenAI API key required")
            return False
        
        try:
            req = urllib2.Request("https://api.openai.com/v1/models")
            req.add_header('Authorization', 'Bearer ' + self.API_KEY)
            
            response = urllib2.urlopen(req, timeout=10)
            data = json.loads(response.read())
            
            if 'data' in data:
                self.available_models = [model['id'] for model in data['data'] if 'gpt' in model['id']]
                self.stdout.println("[AI CONNECTION] OK Connected to OpenAI")
                return True
            return False
        except Exception as e:
            self.stderr.println("[!] OpenAI connection failed: %s" % e)
            return False
    
    def _test_claude_connection(self):
        """Test Claude API connection with actual API call."""
        if not self.API_KEY:
            self.stderr.println("[!] Claude API key required")
            return False
        
        try:
            # Send actual test request to API
            req = urllib2.Request(
                self.API_URL.rstrip('/') + "/messages",
                data=json.dumps({
                    "model": self.MODEL or "claude-3-5-sonnet-20241022",
                    "max_tokens": 5,
                    "messages": [{"role": "user", "content": "ping"}]
                }).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": self.API_KEY,
                    "anthropic-version": "2023-06-01"
                }
            )
            
            resp = urllib2.urlopen(req, timeout=10)
            if resp.getcode() == 200:
                self.stdout.println("[AI CONNECTION] OK Claude API verified")
                # Parse response to get available models info
                self.available_models = [
                    "claude-3-5-sonnet-20241022",
                    "claude-3-opus-20240229",
                    "claude-3-sonnet-20240229"
                ]
                return True
        except urllib2.HTTPError as e:
            if e.code == 429:
                # Rate limited but key and endpoint are valid
                self.stdout.println("[AI CONNECTION] OK Claude API reachable (rate limited)")
                self.available_models = [
                    "claude-3-5-sonnet-20241022",
                    "claude-3-opus-20240229",
                    "claude-3-sonnet-20240229"
                ]
                return True
            else:
                self.stderr.println("[!] Claude API error: %s" % e)
                return False
        except Exception as e:
            self.stderr.println("[!] Claude connection failed: %s" % e)
            return False
        return True
    
    def _test_gemini_connection(self):
        if not self.API_KEY:
            self.stderr.println("[!] Gemini API key required")
            return False
        
        self.available_models = [
            "gemini-1.5-pro",
            "gemini-1.5-flash",
            "gemini-pro"
        ]
        self.stdout.println("[AI CONNECTION] OK Gemini API configured")
        return True

    def _test_azure_foundry_connection(self):
        if not self.API_KEY:
            self.stderr.println("[!] Azure Foundry API key required")
            return False

        if not self.API_URL:
            self.stderr.println("[!] Azure Foundry API URL required")
            return False

        try:
            endpoint_no_query = self.API_URL.split('?', 1)[0].rstrip('/')

            # Try deployments listing first for model discovery when endpoint supports it.
            resource_root = endpoint_no_query
            if "/openai/deployments/" in resource_root:
                resource_root = resource_root.split("/openai/deployments/")[0]
            elif "/openai/v1" in resource_root:
                resource_root = resource_root.split("/openai/v1", 1)[0]

            deployments_url = self._append_api_version(resource_root.rstrip('/') + "/openai/deployments")
            try:
                req = urllib2.Request(deployments_url)
                req.add_header('Content-Type', 'application/json')
                req.add_header('api-key', self.API_KEY)

                response = urllib2.urlopen(req, timeout=10)
                data = json.loads(response.read())

                deployments = []
                if isinstance(data, dict) and isinstance(data.get('data'), list):
                    for deployment in data.get('data'):
                        if isinstance(deployment, dict):
                            dep_name = deployment.get('id') or deployment.get('name')
                            if dep_name:
                                deployments.append(dep_name)

                if deployments:
                    self.available_models = deployments
                    self.stdout.println("[AI CONNECTION] OK Connected to Azure Foundry")
                    self.stdout.println("[AI CONNECTION] Found %d deployment(s)" % len(self.available_models))

                    if self.MODEL not in self.available_models:
                        old_model = self.MODEL
                        self.MODEL = self.available_models[0]
                        self.stdout.println("[AI CONNECTION] Deployment '%s' not found, using '%s'" %
                                          (old_model, self.MODEL))
                    return True

                # Empty deployment list but API reachable.
                self.available_models = [self.MODEL] if self.MODEL else []
                self.stdout.println("[AI CONNECTION] OK Azure Foundry API reachable")
                self.stdout.println("[AI CONNECTION] No deployments returned - using configured deployment name")
                return True
            except Exception as list_error:
                if self.VERBOSE:
                    self.stdout.println("[AI CONNECTION] Deployments listing unavailable, trying chat endpoint: %s" % list_error)

            # Fallback: test the chat completions endpoint directly.
            chat_url = self._build_azure_chat_url(endpoint_no_query)
            req = urllib2.Request(
                self._append_api_version(chat_url),
                data=json.dumps({
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 1,
                    "temperature": 0.0
                }).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "api-key": self.API_KEY
                }
            )

            try:
                response = urllib2.urlopen(req, timeout=10)
                if response.getcode() == 200:
                    self.available_models = [self.MODEL] if self.MODEL else []
                    self.stdout.println("[AI CONNECTION] OK Connected to Azure Foundry (chat endpoint)")
                    return True
            except urllib2.HTTPError as he:
                # 429 still means endpoint/key/deployment are valid but rate-limited.
                if he.code == 429:
                    self.available_models = [self.MODEL] if self.MODEL else []
                    self.stdout.println("[AI CONNECTION] OK Azure Foundry reachable (rate limited)")
                    return True
                raise

            return False

        except Exception as e:
            self.stderr.println("[!] Azure Foundry connection failed: %s" % e)
            return False

    def _build_azure_chat_url(self, endpoint_no_query):
        """Build Azure chat-completions URL from either full endpoint or resource root."""
        base_url = endpoint_no_query.rstrip('/')

        if "/chat/completions" in base_url:
            return base_url
        if "/openai/deployments/" in base_url:
            return base_url + "/chat/completions"
        if not self.MODEL:
            raise Exception("Azure Foundry deployment name is required in Model field")

        deployment_name = urllib.quote(self.MODEL, safe='')
        return "%s/openai/deployments/%s/chat/completions" % (base_url, deployment_name)
    
    def print_logo(self):
        self.stdout.println("")
        self.stdout.println("=" * 65)
        self.stdout.println("")
        self.stdout.println("     SILENTCHAIN AI")
        self.stdout.println("     ---------------")
        self.stdout.println("     AI-Powered OWASP Top 10 Vulnerability Scanning for Burp Suite")
        self.stdout.println("")
        self.stdout.println("     COMMUNITY EDITION v%s" % self.VERSION)
        self.stdout.println("")
        self.stdout.println("     Intelligent | Silent | Adaptive | Comprehensive")
        self.stdout.println("")
        self.stdout.println("=" * 65)
        self.stdout.println("")

    def doPassiveScan(self, baseRequestResponse):
        # Check if passive scanning is enabled
        if not self.PASSIVE_SCANNING_ENABLED:
            return None

        url_str = None
        try:
            req = self.helpers.analyzeRequest(baseRequestResponse)
            url_str = str(req.getUrl())
            if self.VERBOSE:
                self.stdout.println("\n[PASSIVE] URL: %s" % url_str)

            if not self.is_in_scope(url_str):
                if self.VERBOSE:
                    self.stdout.println("[PASSIVE] URL: %s - [SKIP] Out of scope" % url_str)
                return None

            # Skip static file extensions
            if self.should_skip_extension(url_str):
                return None

        except:
            url_str = "Unknown"

        task_id = self.addTask("PASSIVE", url_str, "Queued", baseRequestResponse)
        # Use thread pool instead of raw threading to prevent resource exhaustion
        task = AnalyzeTask(self, baseRequestResponse, url_str, task_id)
        self.thread_pool.submit(task)
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # Community Edition: No active scanning
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return 0

    def is_in_scope(self, url):
        try:
            from java.net import URL as JavaURL
            java_url = JavaURL(url)
            in_scope = self.callbacks.isInScope(java_url)

            if not in_scope:
                if self.VERBOSE:
                    self.stdout.println("[SCOPE] X OUT OF SCOPE: %s" % url)

            return in_scope

        except Exception as e:
            if self.VERBOSE:
                self.stderr.println("[!] Scope check error for %s: %s" % (url, e))
            return False

    def should_skip_extension(self, url):
        """Check if URL has a file extension that should be skipped (static files)"""
        try:
            # Get the path from URL, removing query string
            path = url.split('?')[0].lower()
            # Get the extension (last part after the final dot in the filename)
            if '/' in path:
                filename = path.split('/')[-1]
            else:
                filename = path
            if '.' in filename:
                ext = filename.split('.')[-1]
                if ext in self.SKIP_EXTENSIONS:
                    if self.VERBOSE:
                        self.stdout.println("[SKIP] Static file extension: .%s - %s" % (ext, url[:80]))
                    return True
            return False
        except:
            return False
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        # Check if passive scanning is enabled
        if not self.PASSIVE_SCANNING_ENABLED:
            return

        TOOL_PROXY = 4
        if toolFlag != TOOL_PROXY:
            return

        url_str = None
        try:
            req = self.helpers.analyzeRequest(messageInfo)
            url_str = str(req.getUrl())
            if self.VERBOSE:
                self.stdout.println("\n[HTTP] URL: %s" % url_str)

            if not self.is_in_scope(url_str):
                if self.VERBOSE:
                    self.stdout.println("[HTTP] URL: %s - [SKIP] Out of scope" % url_str)
                return

            # Skip static file extensions
            if self.should_skip_extension(url_str):
                return

        except:
            url_str = "Unknown"

        task_id = self.addTask("HTTP", url_str, "Queued", messageInfo)
        # Submit analysis task to thread pool instead of spawning unlimited threads
        analysis_task = AnalyzeTask(self, messageInfo, url_str, task_id)
        self.thread_pool.submit(analysis_task)

    def analyze(self, messageInfo, url_str=None, task_id=None):
        # Extract host from URL for per-host semaphore
        host = self._extract_host_from_url(url_str or "unknown")
        host_sem = self.get_host_semaphore(host)
        
        # Acquire host semaphore first (narrow), then global (wide) to prevent deadlock
        host_sem.acquire()
        try:
            self.global_semaphore.acquire()
            try:
                try:
                    time_since_last = time.time() - self.last_request_time
                    if time_since_last < self.min_delay:
                        wait_time = self.min_delay - time_since_last
                        if task_id is not None:
                            self.updateTask(task_id, "Waiting (Rate Limit)")
                        time.sleep(wait_time)
                    
                    self.last_request_time = time.time()
                    if task_id is not None:
                        self.updateTask(task_id, "Analyzing")
                    
                    self._perform_analysis(messageInfo, "HTTP", url_str, task_id)
                    
                    if task_id is not None:
                        self.updateTask(task_id, "Completed")
                except Exception as e:
                    self.stderr.println("[!] HTTP error: %s" % e)
                    if task_id is not None:
                        self.updateTask(task_id, "Error: %s" % str(e)[:30])
                    self.updateStats("errors")
                finally:
                    self.refreshUI()
            finally:
                self.global_semaphore.release()
        finally:
            host_sem.release()

    def analyze_forced(self, messageInfo, url_str=None, task_id=None):
        """
        Forced analysis that bypasses deduplication.
        Used for context menu re-analysis of already-analyzed requests.
        """
        # Extract host from URL for per-host semaphore
        host = self._extract_host_from_url(url_str or "unknown")
        host_sem = self.get_host_semaphore(host)
        
        # Acquire global pool cap first, then per-host limit
        self.global_semaphore.acquire()
        try:
            with host_sem:
                try:
                    time_since_last = time.time() - self.last_request_time
                    if time_since_last < self.min_delay:
                        wait_time = self.min_delay - time_since_last
                        if task_id is not None:
                            self.updateTask(task_id, "Waiting (Rate Limit)")
                        time.sleep(wait_time)
                    
                    self.last_request_time = time.time()
                    if task_id is not None:
                        self.updateTask(task_id, "Analyzing (Forced)")
                    
                    # Call _perform_analysis with bypass_dedup=True
                    self._perform_analysis(messageInfo, "CONTEXT", url_str, task_id, bypass_dedup=True)
                    
                    if task_id is not None:
                        self.updateTask(task_id, "Completed")
                except Exception as e:
                    self.stderr.println("[!] Context menu error: %s" % e)
                    if task_id is not None:
                        self.updateTask(task_id, "Error: %s" % str(e)[:30])
                    self.updateStats("errors")
                finally:
                    self.refreshUI()
        finally:
            self.global_semaphore.release()

    def get_host_semaphore(self, host):
        """Get or create per-host semaphore (max 2 concurrent per host)."""
        with self.host_semaphore_lock:
            if host not in self.host_semaphores:
                self.host_semaphores[host] = threading.Semaphore(2)
            return self.host_semaphores[host]
    
    def _extract_host_from_url(self, url_str):
        """Extract hostname from URL string."""
        try:
            import re
            match = re.match(r'https?://([^:/]+)', str(url_str))
            return match.group(1) if match else "unknown"
        except:
            return "unknown"

    def update_table_diff(self, model, new_rows):
        """Differential table update — only modify changed cells, don't wipe and rebuild."""
        current_count = model.getRowCount()
        
        for i, row in enumerate(new_rows):
            if i < current_count:
                # Update existing row only if changed
                for j, val in enumerate(row):
                    try:
                        current_val = str(model.getValueAt(i, j))
                        if current_val != str(val):
                            model.setValueAt(val, i, j)
                    except:
                        model.setValueAt(val, i, j)
            else:
                # Add new row
                model.addRow(row)
        
        # Trim excess rows
        while model.getRowCount() > len(new_rows):
            model.removeRow(model.getRowCount() - 1)

    def smart_truncate_body(self, body, max_len=5000):
        """Smart truncation: keep crucial regions (start + end) with ellipsis indicator."""
        if len(body) <= max_len:
            return body
        
        # Keep first 3000 (usually contains forms, inputs, error messages)
        head_len = 3000
        # Keep last 1000 (usually closing tags, JavaScript, tokens, endpoints)
        tail_len = 1000
        truncated_len = len(body) - head_len - tail_len
        
        if truncated_len > 0:
            return body[:head_len] + "\n...[truncated %d chars]...\n" % truncated_len + body[-tail_len:]
        else:
            return body[:max_len]

    def extract_idor_signals(self, params_sample, url):
        """Detect patterns that may indicate IDOR vulnerability."""
        signals = []
        try:
            import re
            
            # Numeric IDs in URL path
            path_ids = re.findall(r'/(\d{1,10})(?:/|$|\?)', str(url))
            if path_ids:
                signals.append({"type": "path_numeric_id", "values": path_ids[:3]})
            
            # Check for UUID patterns in URL
            if re.search(r'[0-9a-f-]{36}', str(url), re.I):
                signals.append({"type": "path_uuid"})
            
            # Numeric params (likely IDs)
            numeric_params = []
            uuid_params = []
            
            for p in params_sample:
                val = p.get("value", "")
                name = p.get("name", "")
                
                if re.match(r'^\d+$', val) and len(val) <= 10:
                    numeric_params.append({"name": name, "value": val})
                elif re.match(r'^[0-9a-f-]{36}$', val, re.I):
                    uuid_params.append({"name": name, "value": val})
            
            if numeric_params:
                signals.append({"type": "numeric_param", "params": numeric_params[:3]})
            if uuid_params:
                signals.append({"type": "uuid_param", "params": uuid_params[:3]})
            
            # Check for common IDOR parameter names (easy wins for pentesters)
            IDOR_PARAM_NAMES = {
                'id', 'user_id', 'account_id', 'order_id', 'invoice_id',
                'file_id', 'doc_id', 'record_id', 'item_id', 'uid', 'pid',
                'customer_id', 'profile_id', 'token', 'ref', 'key'
            }
            idor_named_params = []
            for p in params_sample:
                name = p.get("name", "").lower()
                # Check if param name matches common IDOR patterns
                if any(idor_name == name or name.endswith('_' + idor_name) for idor_name in IDOR_PARAM_NAMES):
                    idor_named_params.append({"name": p.get("name"), "value": p.get("value", "")[:20]})
            if idor_named_params:
                signals.append({"type": "idor_param_name", "params": idor_named_params[:5]})
        
        except:
            pass
        
        return signals

    def _get_url_hash(self, url, params):
        param_names = sorted([p.getName() for p in params])
        normalized = str(url).split('?')[0] + '|' + '|'.join(param_names)
        # Use SHA-256 instead of MD5 for better cryptographic security
        return hashlib.sha256(normalized.encode('utf-8')).hexdigest()[:32]

    def _get_finding_hash(self, url, title, cwe, param_name=""):
        key = "%s|%s|%s|%s" % (str(url).split('?')[0], title.lower().strip(), cwe, param_name)
        # Use SHA-256 instead of MD5 for better cryptographic security
        return hashlib.sha256(key.encode('utf-8')).hexdigest()

    def _parse_ai_response(self, ai_text):
        """Parse AI response into findings list. Handles repair of malformed JSON."""
        ai_text = ai_text.strip()
        
        # Strip markdown fences
        if ai_text.startswith("```"):
            import re
            ai_text = re.sub(r'^```(?:json)?\n?|```$', '', ai_text, flags=re.MULTILINE).strip()
        
        # Try to extract JSON array or object
        start = ai_text.find('[')
        end = ai_text.rfind(']')
        if start != -1 and end != -1:
            ai_text = ai_text[start:end + 1]
        elif ai_text.find('{') != -1:
            obj_start = ai_text.find('{')
            obj_end = ai_text.rfind('}')
            if obj_start != -1 and obj_end != -1:
                ai_text = '[' + ai_text[obj_start:obj_end + 1] + ']'
        
        try:
            findings = json.loads(ai_text)
            return findings if isinstance(findings, list) else [findings]
        except ValueError:
            # JSON parse failed, attempt repair
            return self._repair_json(ai_text)

    def _repair_json(self, ai_text):
        """Attempt to repair malformed JSON and extract findings."""
        try:
            import re
            original_text = ai_text
            
            # Strategy 1: Fix unterminated strings
            lines = ai_text.split('\n')
            fixed_lines = []
            for line in lines:
                if not line.strip():
                    fixed_lines.append(line)
                    continue
                
                quote_positions = []
                i = 0
                while i < len(line):
                    if line[i] == '"' and (i == 0 or line[i-1] != '\\'):
                        quote_positions.append(i)
                    i += 1
                
                if len(quote_positions) % 2 == 1:
                    line = line.rstrip()
                    if line.endswith(',') or line.endswith('}') or line.endswith(']'):
                        line = line[:-1] + '"' + line[-1]
                    elif not line.endswith('"'):
                        line = line + '"'
                
                fixed_lines.append(line)
            
            ai_text = '\n'.join(fixed_lines)
            ai_text = re.sub(r',(\s*[}\]])', r'\1', ai_text)
            ai_text = ai_text.strip()
            
            if not ai_text.startswith('['):
                if ai_text.startswith('{'):
                    ai_text = '[' + ai_text
                else:
                    start_obj = ai_text.find('{')
                    if start_obj != -1:
                        ai_text = '[' + ai_text[start_obj:]
            
            if not ai_text.endswith(']'):
                if ai_text.endswith('}'):
                    ai_text = ai_text + ']'
                else:
                    end_obj = ai_text.rfind('}')
                    if end_obj != -1:
                        ai_text = ai_text[:end_obj+1] + ']'
            
            final_bracket = ai_text.rfind(']')
            if final_bracket != -1 and final_bracket < len(ai_text) - 1:
                ai_text = ai_text[:final_bracket + 1]
            
            findings = json.loads(ai_text)
            self.stdout.println("[+] JSON successfully repaired")
            return findings if isinstance(findings, list) else [findings]
        
        except Exception:
            self.stderr.println("[!] JSON repair failed")
            return []

    def _perform_analysis(self, messageInfo, source, url_str=None, task_id=None, bypass_dedup=False):
        try:
            req = self.helpers.analyzeRequest(messageInfo)
            res = self.helpers.analyzeResponse(messageInfo.getResponse())
            url = str(req.getUrl())
            
            if not url_str:
                url_str = url
            
            params = req.getParameters()
            url_hash = self._get_url_hash(url, params)
            
            # Check deduplication unless bypass requested (e.g., context menu)
            if not bypass_dedup:
                with self.url_lock:
                    if url_hash in self.processed_urls:
                        if self.VERBOSE:
                            self.stdout.println("[%s] URL: %s - [SKIP] Already analyzed" % (source, url_str))
                        if task_id is not None:
                            self.updateTask(task_id, "Skipped (Already Analyzed)")
                        self.updateStats("skipped_duplicate")
                        return
                    
                    self.processed_urls.add(url_hash)
            else:
                # Context menu re-analysis - force fresh analysis
                if self.VERBOSE:
                    self.stdout.println("[%s] URL: %s - [FORCE] Bypassing deduplication" % (source, url_str))

            request_bytes = messageInfo.getRequest()
            try:
                # Use Burp's helper for safe string conversion
                req_body = self.helpers.bytesToString(request_bytes[req.getBodyOffset():])[:2000]
            except Exception as e:
                if self.VERBOSE:
                    self.stdout.println("[DEBUG] Request body decode error: %s" % e)
                req_body = "[Binary/non-UTF8 content]"
            
            req_headers = [str(h) for h in req.getHeaders()[:10]]
            
            response_bytes = messageInfo.getResponse()
            try:
                # Use Burp's helper for safe string conversion + smart truncation
                raw_body = self.helpers.bytesToString(response_bytes[res.getBodyOffset():])
                res_body = self.smart_truncate_body(raw_body, max_len=5000)
            except Exception as e:
                if self.VERBOSE:
                    self.stdout.println("[DEBUG] Response body decode error: %s" % e)
                res_body = "[Binary/non-UTF8 content]"
            
            res_headers = [str(h) for h in res.getHeaders()[:10]]

            params_sample = [{"name": p.getName(), "value": p.getValue()[:150], 
                            "type": str(p.getType())} for p in params[:5]]

            # Extract IDOR signals (numeric IDs, UUIDs, etc)
            idor_signals = self.extract_idor_signals(params_sample, url)

            data = {
                "url": url, "method": req.getMethod(), "status": res.getStatusCode(),
                "mime_type": res.getStatedMimeType(), "params_count": len(params),
                "params_sample": params_sample, "request_headers": req_headers,
                "request_body": req_body, "response_headers": res_headers,
                "response_body": res_body, "idor_signals": idor_signals
            }

            request_signature = self._get_request_signature(data)

            # Persistent cache lookup (reduces repeat AI calls across sessions)
            cached_findings = None
            if not bypass_dedup:
                cached_findings = self._get_cached_findings_for_signature(request_signature)

            if cached_findings:
                findings = cached_findings
                self.updateStats("cached_reused")
                self.updateStats("analyzed")
                if self.VERBOSE:
                    self.stdout.println(
                        "[%s] [CACHE HIT] %s | signature=%s | findings=%d | no API call" %
                        (source, url_str, request_signature[:12], len(findings))
                    )
            else:
                if self.VERBOSE:
                    self.stdout.println(
                        "[%s] [AI REQUEST] method=%s status=%s params=%d reqBody=%dB resBody=%dB" %
                        (source, data.get("method", "?"), data.get("status", "?"),
                         data.get("params_count", 0), len(req_body), len(res_body))
                    )
                    self.stdout.println(
                        "[%s] [AI REQUEST] reqHeaders=%d resHeaders=%d model=%s" %
                        (source, len(req_headers), len(res_headers), self.MODEL)
                    )

                if self.VERBOSE:
                    self.stdout.println("[%s] Analyzing (NEW)" % source)

                ai_text = self.ask_ai(self.build_prompt(data))

                if not ai_text:
                    if self.VERBOSE:
                        self.stdout.println("[%s] [ERROR] No AI response" % source)
                    if task_id is not None:
                        self.updateTask(task_id, "Error (No AI Response)")
                    self.updateStats("errors")
                    return

                self.updateStats("analyzed")

                ai_text = ai_text.strip()
                if self.VERBOSE:
                    self.stdout.println("[%s] [AI RESPONSE] received=%d chars" % (source, len(ai_text)))

                # Parse AI response (handles markdown, JSON repair, etc)
                findings = self._parse_ai_response(ai_text)
                
                if not findings:
                    self.stderr.println("[!] Failed to extract findings from AI response")
                    if task_id is not None:
                        self.updateTask(task_id, "Error (JSON Parse Failed)")
                    self.updateStats("errors")
                    return

                # Store fresh AI result in persistent cache for future reuse
                self._store_cached_findings(request_signature, url, findings)
            
            if not isinstance(findings, list):
                findings = [findings]

            if self.VERBOSE:
                sample_titles = []
                for f_item in findings[:3]:
                    if isinstance(f_item, dict):
                        sample_titles.append(str(f_item.get("title", "AI Finding"))[:40])
                summary = ", ".join(sample_titles) if sample_titles else "none"
                self.stdout.println(
                    "[%s] [AI PARSED] findings=%d sample=%s" % (source, len(findings), summary)
                )

            created = 0
            skipped_dup = 0
            skipped_low_conf = 0

            for item in findings:
                title = item.get("title", "AI Finding")
                severity = item.get("severity", "information").lower().strip()
                ai_conf = item.get("confidence", 50)
                
                # Ensure ai_conf is an integer
                try:
                    ai_conf = int(ai_conf)
                except (ValueError, TypeError):
                    ai_conf = 50  # Default if conversion fails
                
                detail = item.get("detail", "")
                cwe = item.get("cwe", "")
                
                param_name = ""
                if params_sample:
                    param_name = params_sample[0].get("name", "")

                burp_conf = map_confidence(ai_conf)
                if not burp_conf:
                    skipped_low_conf += 1
                    if self.VERBOSE:
                        self.stdout.println("[%s] URL: %s - [SKIP] Low confidence" % (source, url_str))
                    self.updateStats("skipped_low_confidence")
                    continue

                finding_hash = self._get_finding_hash(url, title, cwe, param_name)
                with self.findings_lock:
                    if finding_hash in self.findings_cache:
                        skipped_dup += 1
                        if self.VERBOSE:
                            self.stdout.println("[%s] URL: %s - [SKIP] Duplicate finding" % (source, url_str))
                        self.updateStats("skipped_duplicate")
                        continue
                    self.findings_cache[finding_hash] = True

                severity = VALID_SEVERITIES.get(severity, "Information")

                detail_parts = []
                detail_parts.append("<b>Description:</b><br>%s<br>" % detail)
                detail_parts.append("<br><b>AI Confidence:</b> %d%%<br>" % ai_conf)
                
                # Add AI-identified vulnerable parameter if present
                ai_param = item.get("param", "")
                if ai_param:
                    detail_parts.append("<br><b>Vulnerable Parameter (AI):</b> <code>%s</code><br>" % ai_param)
                
                # Add evidence field if present
                if item.get("evidence"):
                    evidence_text = str(item.get("evidence", ""))[:500]
                    detail_parts.append("<br><b>Evidence:</b><br><code>%s</code><br>" % evidence_text)
                
                if params_sample:
                    detail_parts.append("<br><b>Affected Parameter(s):</b><br>")
                    for param in params_sample[:3]:
                        param_name = param.get("name", "")
                        param_type = param.get("type", 0)
                        type_str = {0: "URL", 1: "Body", 2: "Cookie"}.get(param_type, "Unknown")
                        detail_parts.append("<code>%s (%s parameter)</code><br>" % (param_name, type_str))
                
                if item.get("cwe"):
                    cwe_id = item.get("cwe")
                    detail_parts.append("<br><b>CWE:</b><br>%s<br>" % cwe_id)
                    detail_parts.append("<a href='https://cwe.mitre.org/data/definitions/%s.html'>View CWE Details</a><br>" % 
                                       cwe_id.replace("CWE-", ""))
                
                if item.get("owasp"):
                    detail_parts.append("<br><b>OWASP:</b><br>%s<br>" % item.get("owasp"))
                
                if item.get("remediation"):
                    detail_parts.append("<br><b>Remediation:</b><br>%s<br>" % item.get("remediation"))
                
                detail_parts.append("<br><br><b>Note:</b><br>")
                detail_parts.append("<i>This finding was detected through passive AI analysis.</i>")
                
                full_detail = "".join(detail_parts)

                issue = CustomScanIssue(messageInfo.getHttpService(), req.getUrl(),
                                       [messageInfo], title, full_detail, severity, burp_conf)
                self.callbacks.addScanIssue(issue)
                created += 1
                self.updateStats("findings_created")
                
                self.add_finding(url, title, severity, burp_conf)

            if self.VERBOSE:
                self.stdout.println("[%s] Created:%d | Dup:%d | LowConf:%d" %
                                   (source, int(created), int(skipped_dup), int(skipped_low_conf)))

        except Exception as e:
            self.stderr.println("[!] %s error: %s" % (source, e))
            self.updateStats("errors")

    def build_prompt(self, data):
        return (
            "Security expert. Output ONLY JSON array. NO markdown.\n"
            "Analyze for ALL of the following:\n"
            "1. OWASP Top 10 (2021) - SQL Injection, XSS, Authentication flaws, etc.\n"
            "2. IDOR/Broken Object Level Auth - look for numeric/sequential IDs in params\n"
            "3. Mass Assignment - extra params in POST bodies not validated\n"
            "4. SSRF - URL params, redirect params, webhook endpoints\n"
            "5. JWT weaknesses - alg:none, weak secrets in Authorization header\n"
            "6. GraphQL exploitation - introspection, batching, if body contains 'query' or '__schema'\n"
            "7. OAuth misconfigs - redirect_uri, state param missing, token leakage\n"
            "8. HTTP Request Smuggling hints - Transfer-Encoding + Content-Length conflicts\n"
            "9. Cache Poisoning - X-Forwarded-Host, X-Original-URL, X-Forwarded-Proto headers\n"
            "10. Business Logic flaws - price/quantity params, role/permission params, discount logic\n"
            "11. Information Disclosure - stack traces, internal IPs, API keys, secrets in responses\n"
            "12. Prototype Pollution - __proto__, constructor in JSON params, Object.assign usage\n"
            "13. Missing security headers - CSP, HSTS, X-Frame-Options, X-Content-Type-Options\n"
            "14. Sensitive data in responses - PII, tokens, internal paths, debug info\n"
            "15. API versioning issues - v1/v2 endpoints with different access controls\n"
            "Flag confidence=0 if no evidence. Only report confidence>=50.\n"
            "Format: [{\"title\":str,\"severity\":\"High|Medium|Low|Information\","
            "\"confidence\":0-100,\"detail\":str,\"cwe\":str,"
            "\"owasp\":str,\"remediation\":str,\"param\":str,\"evidence\":str}]\n"
            "HTTP Data:\n%s\n"
        ) % json.dumps(data, indent=2)

    def ask_ai(self, prompt):
        try:
            if self.AI_PROVIDER == "Ollama":
                return self._ask_ollama(prompt)
            elif self.AI_PROVIDER == "OpenAI":
                return self._ask_openai(prompt)
            elif self.AI_PROVIDER == "Claude":
                return self._ask_claude(prompt)
            elif self.AI_PROVIDER == "Gemini":
                return self._ask_gemini(prompt)
            elif self.AI_PROVIDER == "Azure Foundry":
                return self._ask_azure_foundry(prompt)
            else:
                self.stderr.println("[!] Unknown AI provider: %s" % self.AI_PROVIDER)
                return None
        except Exception as e:
            self.stderr.println("[!] AI request failed: %s" % e)
            return None
    
    def _ask_ollama(self, prompt):
        """Send request to Ollama with timeout and retry logic"""
        generate_url = self.API_URL.rstrip('/') + "/api/generate"
        
        payload = {
            "model": self.MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.0,
                "num_predict": self.MAX_TOKENS
            }
        }
        
        max_retries = 2
        retry_count = 0
        
        while retry_count <= max_retries:
            try:
                if self.VERBOSE and retry_count > 0:
                    self.stdout.println("[DEBUG] Retry attempt %d/%d..." % (retry_count, max_retries))
                
                req = urllib2.Request(generate_url, data=json.dumps(payload).encode("utf-8"),
                                    headers={"Content-Type": "application/json"})
                
                # Use configurable timeout
                resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
                
                raw = resp.read().decode("utf-8", "ignore")
                response_json = json.loads(raw)
                ai_response = response_json.get("response", "").strip()
                
                if response_json.get("done_reason") == "length":
                    ai_response = self._fix_truncated_json(ai_response)
                
                return ai_response
                
            except urllib2.URLError as e:
                if "timed out" in str(e) or "timeout" in str(e).lower():
                    retry_count += 1
                    if retry_count <= max_retries:
                        self.stderr.println("[!] Request timeout, retrying... (%d/%d)" % (retry_count, max_retries))
                        time.sleep(2)  # Wait 2 seconds before retry
                    else:
                        self.stderr.println("[!] Request failed after %d retries (timeout: %ds)" % 
                                          (max_retries, int(self.AI_REQUEST_TIMEOUT)))
                        self.stderr.println("[!] Try increasing timeout in Settings or using a faster model")
                        raise
                else:
                    # Non-timeout error, don't retry
                    raise
            except Exception as e:
                # Other errors, don't retry
                raise
        
        return None
    
    def _ask_openai(self, prompt):
        """Send request to OpenAI with configurable timeout"""
        req = urllib2.Request(
            self.API_URL.rstrip('/') + "/chat/completions",
            data=json.dumps({
                "model": self.MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": self.MAX_TOKENS,
                "temperature": 0.0
            }).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self.API_KEY
            }
        )
        
        resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
        data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]
    
    def _ask_claude(self, prompt):
        """Send request to Claude with configurable timeout"""
        req = urllib2.Request(
            self.API_URL.rstrip('/') + "/messages",
            data=json.dumps({
                "model": self.MODEL,
                "max_tokens": self.MAX_TOKENS,
                "messages": [{"role": "user", "content": prompt}]
            }).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.API_KEY,
                "anthropic-version": "2023-06-01"
            }
        )
        
        resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
        data = json.loads(resp.read())
        return data["content"][0]["text"]
    
    def _ask_gemini(self, prompt):
        """Send request to Google Gemini with configurable timeout"""
        req = urllib2.Request(
            self.API_URL.rstrip('/') + "/models/%s:generateContent?key=%s" % (self.MODEL, self.API_KEY),
            data=json.dumps({
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "maxOutputTokens": self.MAX_TOKENS,
                    "temperature": 0.0
                }
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        
        resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
        data = json.loads(resp.read())
        return data["candidates"][0]["content"]["parts"][0]["text"]

    def _append_api_version(self, url):
        if "api-version=" in url:
            return url
        separator = '&' if '?' in url else '?'
        version = self.AZURE_API_VERSION if self.AZURE_API_VERSION else "2024-06-01"
        return url + separator + "api-version=%s" % version

    def _ask_azure_foundry(self, prompt):
        """Send request to Azure AI Foundry (Azure OpenAI-compatible chat completions API)."""
        if not self.API_KEY:
            raise Exception("Azure Foundry API key required")

        if not self.API_URL:
            raise Exception("Azure Foundry API URL required")

        base_url = self.API_URL.split('?', 1)[0].rstrip('/')
        chat_url = self._build_azure_chat_url(base_url)

        chat_url = self._append_api_version(chat_url)

        req = urllib2.Request(
            chat_url,
            data=json.dumps({
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": self.MAX_TOKENS,
                "temperature": 0.0
            }).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "api-key": self.API_KEY
            }
        )

        resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
        data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]
    
    def _fix_truncated_json(self, text):
        if not text: return "[]"
        try:
            json.loads(text)
            return text
        except: pass
        
        last_brace = text.rfind('}')
        if last_brace > 0:
            prefix = text[:last_brace + 1]
            if prefix.count('[') > prefix.count(']'):
                try:
                    fixed = prefix + '\n]'
                    json.loads(fixed)
                    return fixed
                except: pass
        return "[]"


# UI Component Classes
class StatusCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        
        if value:
            status = str(value)
            # Priority order for status colors
            if "Cancelled" in status:
                c.setForeground(Color(150, 0, 0))  # Dark red
                c.setFont(Font("Monospaced", Font.BOLD, 12))
            elif "Paused" in status:
                c.setForeground(Color(150, 150, 0))  # Dark yellow
                c.setFont(Font("Monospaced", Font.BOLD, 12))
            elif "Error" in status:
                c.setForeground(Color(200, 0, 0))  # Red
                c.setFont(Font("Monospaced", Font.BOLD, 12))
            elif "Skipped" in status:
                c.setForeground(Color(200, 100, 0))  # Orange
            elif "Completed" in status:
                c.setForeground(Color(0, 150, 0))  # Green
            elif "Analyzing" in status or "Waiting" in status:
                c.setForeground(Color(0, 100, 200))  # Blue
            elif "Queued" in status:
                c.setForeground(Color(100, 100, 100))  # Gray
            else:
                c.setForeground(Color.BLACK)
        
        return c

class SeverityCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        c.setFont(Font("Monospaced", Font.BOLD, 12))
        
        if value:
            severity = str(value)
            if severity == "High":
                c.setForeground(Color.WHITE)
                c.setBackground(Color(200, 0, 0))
            elif severity == "Medium":
                c.setForeground(Color.WHITE)
                c.setBackground(Color(255, 140, 0))
            elif severity == "Low":
                c.setForeground(Color.BLACK)
                c.setBackground(Color(255, 200, 0))
            elif severity == "Information":
                c.setForeground(Color.WHITE)
                c.setBackground(Color(0, 100, 200))
            else:
                c.setForeground(Color.BLACK)
                c.setBackground(Color.WHITE)
        
        return c

class ConfidenceCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        c.setFont(Font("Monospaced", Font.BOLD, 11))
        
        if value:
            confidence = str(value)
            if confidence == "Certain":
                c.setForeground(Color(0, 150, 0))
            elif confidence == "Firm":
                c.setForeground(Color(0, 100, 200))
            elif confidence == "Tentative":
                c.setForeground(Color(200, 100, 0))
            else:
                c.setForeground(Color.BLACK)
        
        return c

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, messages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._messages = messages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self): return self._url
    def getIssueName(self): return self._name
    def getIssueType(self): return 0x80000003
    def getSeverity(self): return self._severity
    def getConfidence(self): return self._confidence
    def getIssueDetail(self): return self._detail
    def getHttpMessages(self): return self._messages
    def getHttpService(self): return self._httpService
    def getIssueBackground(self): return None
    def getRemediationBackground(self): return None
    def getRemediationDetail(self): return None
