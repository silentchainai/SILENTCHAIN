# -*- coding: utf-8 -*-
# Burp Suite Python Extension: SILENTCHAIN AI - COMMUNITY EDITION
# Version: 1.0.9
# Release Date: 2025-02-02
# License: MIT License
#
# COMMUNITY EDITION - AI-Powered Security Scanner
# For active verification and Phase 2 testing, upgrade to Professional Edition
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
import json
import threading
import urllib2
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

        callbacks.setExtensionName("SILENTCHAIN AI - Community Edition")
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)

        # Version Information
        self.VERSION = "1.0.9"
        self.EDITION = "Community"
        self.RELEASE_DATE = "2025-02-02"
        
        # Display version in extension name
        callbacks.setExtensionName("SILENTCHAIN AI - %s Edition v%s" % (self.EDITION, self.VERSION))

        # Configuration file path (in user's home directory)
        import os
        self.config_file = os.path.join(os.path.expanduser("~"), ".silentchain_config.json")
        
        # AI Provider Settings (defaults - will be overridden by saved config)
        self.AI_PROVIDER = "Ollama"  # Options: Ollama, OpenAI, Claude, Gemini
        self.API_URL = "http://localhost:11434"
        self.API_KEY = ""  # For OpenAI, Claude, Gemini
        self.MODEL = "deepseek-r1:latest"
        self.MAX_TOKENS = 2048
        self.AI_REQUEST_TIMEOUT = 60  # Timeout for AI requests in seconds (default: 60)
        self.available_models = []

        self.VERBOSE = True
        self.THEME = "Dark"  # Options: Dark, Light
        self.PASSIVE_SCANNING_ENABLED = True  # Enable/disable passive scanning (context menu still works)

        # File extensions to skip during analysis (static/non-security-relevant files)
        self.SKIP_EXTENSIONS = ["js", "gif", "jpg", "png", "ico", "css", "woff", "woff2", "ttf", "svg"]

        # Load saved configuration (if exists)
        self.load_config()
        
        # Console tracking for UI panel
        self.console_messages = []
        self.console_lock = threading.Lock()
        self.max_console_messages = 1000
        
        # Findings tracking for Findings panel
        self.findings_list = []
        self.findings_lock_ui = threading.Lock()
        
        self.findings_cache = {}
        self.findings_lock = threading.Lock()
        
        # Context menu debounce
        self.context_menu_last_invoke = {}
        self.context_menu_debounce_time = 1.0
        self.context_menu_lock = threading.Lock()
        
        self.processed_urls = set()
        self.url_lock = threading.Lock()
        self.semaphore = threading.Semaphore(1)
        self.last_request_time = 0
        self.min_delay = 4.0

        # Task tracking
        self.tasks = []
        self.tasks_lock = threading.Lock()
        self.stats = {
            "total_requests": 0,
            "analyzed": 0,
            "skipped_duplicate": 0,
            "skipped_rate_limit": 0,
            "skipped_low_confidence": 0,
            "findings_created": 0,
            "errors": 0
        }
        self.stats_lock = threading.Lock()

        # Create UI
        self.initUI()
        
        self.log_to_console("=== SILENTCHAIN AI - Community Edition Initialized ===")
        self.log_to_console("Console panel is active and logging...")
        
        # Force immediate UI refresh
        self.refreshUI()
        
        # Display logo
        self.print_logo()
        
        # Test AI connection and fetch models
        connection_ok = self.test_ai_connection()
        
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
        self.stdout.println("[*] For active verification, upgrade to Professional Edition")
        self.stdout.println("[*] Visit: https://silentchain.ai for more information")
        
        if not connection_ok:
            self.stderr.println("\n[!] WARNING: AI connection test failed!")
            self.stderr.println("[!] Extension will not function properly until connection is established.")
            self.stderr.println("[!] Please check Settings and verify your AI configuration.")

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
        titleLabel = JLabel("SILENTCHAIN AI - Community Edition")
        titleLabel.setFont(Font("Monospaced", Font.BOLD, 16))
        titlePanel = JPanel()
        titlePanel.add(titleLabel)
        topPanel.add(titlePanel)
        
        # Edition notice
        editionLabel = JLabel("AI-Powered Security Scanner")
        editionLabel.setFont(Font("Dialog", Font.ITALIC, 12))
        editionLabel.setForeground(Color(0, 100, 200))
        editionPanel = JPanel()
        editionPanel.add(editionLabel)
        topPanel.add(editionPanel)

        # Website link
        from java.awt import Cursor
        from java.awt.event import MouseAdapter
        websiteLabel = JLabel("https://silentchain.ai")
        websiteLabel.setFont(Font("Dialog", Font.PLAIN, 11))
        websiteLabel.setForeground(Color(0, 100, 200))
        websiteLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))

        class WebsiteLinkListener(MouseAdapter):
            def __init__(self, extender):
                self.extender = extender

            def mouseClicked(self, e):
                try:
                    import webbrowser
                    webbrowser.open("https://silentchain.ai")
                except:
                    self.extender.stdout.println("[INFO] Visit: https://silentchain.ai")

        websiteLabel.addMouseListener(WebsiteLinkListener(self))
        websitePanel = JPanel()
        websitePanel.add(websiteLabel)
        topPanel.add(websitePanel)
        
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
        
        # Control panel
        controlPanel = JPanel()
        
        # Settings button
        self.settingsButton = JButton("Settings", actionPerformed=self.openSettings)
        self.settingsButton.setBackground(Color(100, 100, 200))
        self.settingsButton.setForeground(Color.WHITE)
        
        self.clearButton = JButton("Clear Completed", actionPerformed=self.clearCompleted)
        
        # Cancel/Pause all buttons (kill switches)
        self.cancelAllButton = JButton("Cancel All Tasks", actionPerformed=self.cancelAllTasks)
        self.cancelAllButton.setBackground(Color(200, 0, 0))  # Red
        self.cancelAllButton.setForeground(Color.WHITE)
        
        self.pauseAllButton = JButton("Pause All Tasks", actionPerformed=self.pauseAllTasks)
        self.pauseAllButton.setBackground(Color(200, 150, 0))  # Orange
        self.pauseAllButton.setForeground(Color.BLACK)
        
        # Check for Updates button
        self.upgradeButton = JButton("Check for Updates", actionPerformed=self.openUpgradePage)
        self.upgradeButton.setBackground(Color(0, 150, 0))
        self.upgradeButton.setForeground(Color.WHITE)
        
        controlPanel.add(self.settingsButton)
        controlPanel.add(self.clearButton)
        controlPanel.add(self.cancelAllButton)
        controlPanel.add(self.pauseAllButton)
        controlPanel.add(self.upgradeButton)
        topPanel.add(controlPanel)
        
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
        if self.THEME == "Light":
            # Light theme: White background with charcoal text
            self.consoleTextArea.setBackground(Color.WHITE)
            self.consoleTextArea.setForeground(Color(0x36, 0x45, 0x4F))  # Charcoal #36454F
        else:
            # Dark theme: Charcoal background with light grey text
            self.consoleTextArea.setBackground(Color(0x32, 0x33, 0x34))  # #323334
            self.consoleTextArea.setForeground(Color(0xC4, 0xC6, 0xC7))  # #C4C6C7

    def refreshUI(self, event=None):
        class RefreshRunnable(Runnable):
            def __init__(self, extender):
                self.extender = extender
            
            def run(self):
                # Update stats
                with self.extender.stats_lock:
                    for key, label in self.extender.statsLabels.items():
                        label.setText(str(self.extender.stats.get(key, 0)))
                
                # Update task table
                self.extender.taskTableModel.setRowCount(0)
                with self.extender.tasks_lock:
                    for task in self.extender.tasks[-100:]:
                        duration = ""
                        if task.get("end_time"):
                            duration = "%.2fs" % (task["end_time"] - task["start_time"])
                        elif task.get("start_time"):
                            duration = "%.2fs" % (time.time() - task["start_time"])
                        
                        self.extender.taskTableModel.addRow([
                            task.get("timestamp", ""),
                            task.get("type", ""),
                            task.get("url", "")[:100],
                            task.get("status", ""),
                            duration
                        ])
                
                # Update findings table
                self.extender.findingsTableModel.setRowCount(0)
                
                severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Information": 0}
                total_findings = 0
                
                with self.extender.findings_lock_ui:
                    for finding in self.extender.findings_list:
                        total_findings += 1
                        severity = finding.get("severity", "Information")
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                        
                        self.extender.findingsTableModel.addRow([
                            finding.get("discovered_at", ""),
                            finding.get("url", "")[:100],
                            finding.get("title", "")[:50],
                            severity,
                            finding.get("confidence", "")
                        ])
                
                self.extender.findingsStatsLabel.setText(
                    "Total: %d | High: %d | Medium: %d | Low: %d | Info: %d" % 
                    (total_findings, severity_counts["High"], severity_counts["Medium"], 
                     severity_counts["Low"], severity_counts["Information"])
                )
                
                # Update Console
                with self.extender.console_lock:
                    console_text = "\n".join(self.extender.console_messages)

                    # Save scroll state before updating text
                    was_scrolled = self.extender.console_user_scrolled
                    caret_pos = self.extender.consoleTextArea.getCaretPosition()

                    self.extender.consoleTextArea.setText(console_text)

                    if was_scrolled:
                        # Restore approximate position (clamped to new text length)
                        try:
                            new_pos = min(caret_pos, len(console_text))
                            self.extender.consoleTextArea.setCaretPosition(new_pos)
                            self.extender.console_user_scrolled = True  # Restore flag
                        except:
                            pass
                    else:
                        # Scroll to bottom
                        try:
                            self.extender.consoleTextArea.setCaretPosition(len(console_text))
                        except:
                            pass
        
        SwingUtilities.invokeLater(RefreshRunnable(self))

    def start_auto_refresh_timer(self):
        """Auto-refresh UI and check for stuck tasks"""
        def refresh_timer():
            check_interval = 0
            while True:
                time.sleep(2)
                self.refreshUI()
                
                # Check for stuck tasks every 30 seconds (15 refresh cycles)
                check_interval += 1
                if check_interval >= 15:
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
                
                # Load settings
                self.AI_PROVIDER = config.get("ai_provider", self.AI_PROVIDER)
                self.API_URL = config.get("api_url", self.API_URL)
                self.API_KEY = config.get("api_key", self.API_KEY)
                self.MODEL = config.get("model", self.MODEL)
                self.MAX_TOKENS = config.get("max_tokens", self.MAX_TOKENS)
                self.AI_REQUEST_TIMEOUT = config.get("ai_request_timeout", self.AI_REQUEST_TIMEOUT)
                self.VERBOSE = config.get("verbose", self.VERBOSE)
                self.THEME = config.get("theme", self.THEME)
                self.PASSIVE_SCANNING_ENABLED = config.get("passive_scanning_enabled", self.PASSIVE_SCANNING_ENABLED)

                self.stdout.println("\n[CONFIG] Loaded saved configuration from %s" % self.config_file)
                self.stdout.println("[CONFIG] Provider: %s | Model: %s" % (self.AI_PROVIDER, self.MODEL))
            else:
                self.stdout.println("\n[CONFIG] No saved configuration found - using defaults")
                self.stdout.println("[CONFIG] Config will be saved to: %s" % self.config_file)
        except Exception as e:
            self.stderr.println("[!] Failed to load config: %s" % e)
            self.stderr.println("[!] Using default settings")
    
    def save_config(self):
        """Save configuration to disk"""
        try:
            config = {
                "ai_provider": self.AI_PROVIDER,
                "api_url": self.API_URL,
                "api_key": self.API_KEY,
                "model": self.MODEL,
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
    
    def openUpgradePage(self, event):
        """Open updates page in browser"""
        self.stdout.println("\n[UPDATE] Checking for updates...")
        self.stdout.println("[UPDATE] Visit https://silentchain.ai/?referral=silentchain_community")

        try:
            import webbrowser
            webbrowser.open("https://silentchain.ai/?referral=silentchain_community")
        except:
            self.stdout.println("[UPDATE] Please visit: https://silentchain.ai/?referral=silentchain_community")
    
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
        providerCombo = JComboBox(["Ollama", "OpenAI", "Claude", "Gemini"])
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
                    "Gemini": "https://generativelanguage.googleapis.com/v1"
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
            self.stdout.println("[SETTINGS] Fetching models...")
            if self.test_ai_connection():
                modelCombo.removeAllItems()
                for model in self.available_models:
                    modelCombo.addItem(model)
                self.stdout.println("[SETTINGS] Models refreshed")
        
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
            old_provider = self.AI_PROVIDER
            old_url = self.API_URL
            old_key = self.API_KEY
            
            self.AI_PROVIDER = str(providerCombo.getSelectedItem())
            self.API_URL = apiUrlField.getText()
            self.API_KEY = str(apiKeyField.getPassword())
            
            success = self.test_ai_connection()
            
            if not success:
                self.AI_PROVIDER = old_provider
                self.API_URL = old_url
                self.API_KEY = old_key
        
        testBtn.addActionListener(testConnection)
        aiPanel.add(testBtn, gbc)
        row += 1
        
        gbc.gridy = row
        helpText = JTextArea(
            "Provider-specific URLs:\n\n"
            "Ollama: http://localhost:11434\n"
            "OpenAI: https://api.openai.com/v1\n"
            "Claude: https://api.anthropic.com/v1\n"
            "Gemini: https://generativelanguage.googleapis.com/v1\n\n"
            "API Keys required for: OpenAI, Claude, Gemini"
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
        themeCombo = JComboBox(["Dark", "Light"])
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
        debugTasksBtn.setBackground(Color(100, 100, 100))
        debugTasksBtn.setForeground(Color.WHITE)
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
        upgradeNotice = JTextArea(
            "COMMUNITY EDITION - Passive Analysis Only\n\n"
            "This edition provides AI-powered passive security analysis.\n\n"
            "Upgrade to Professional Edition for:\n"
            "- Phase 2 active verification\n"
            "- Advanced payload libraries (OWASP, custom)\n"
            "- WAF detection and evasion\n"
            "- Out-of-band (OOB) testing\n"
            "- Burp Intruder integration\n"
            "- Priority support\n\n"
            "Visit https://silentchain.ai for more information"
        )
        upgradeNotice.setEditable(False)
        upgradeNotice.setBackground(Color(255, 255, 200))
        upgradeNotice.setFont(Font("Dialog", Font.PLAIN, 11))
        advancedPanel.add(upgradeNotice, gbc)
        
        tabbedPane.addTab("Advanced", advancedPanel)
        
        # BUTTONS
        buttonPanel = JPanel()
        
        def saveSettings(e):
            # Save AI Provider settings
            self.AI_PROVIDER = str(providerCombo.getSelectedItem())
            self.API_URL = apiUrlField.getText()
            self.API_KEY = str(apiKeyField.getPassword())
            self.MODEL = str(modelCombo.getSelectedItem())
            try:
                self.MAX_TOKENS = int(maxTokensField.getText())
            except ValueError:
                self.MAX_TOKENS = 2048
                self.stderr.println("[!] Invalid Max Tokens value, using default: 2048")
            
            # Save Advanced settings
            self.PASSIVE_SCANNING_ENABLED = passiveScanCheck.isSelected()
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
        
        self.refreshUI()
    
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
            return len(self.tasks) - 1

    def updateTask(self, task_id, status, error=None):
        with self.tasks_lock:
            if task_id < len(self.tasks):
                self.tasks[task_id]["status"] = status
                self.tasks[task_id]["end_time"] = time.time()
                if error:
                    self.tasks[task_id]["error"] = error

    def updateStats(self, stat_key, increment=1):
        with self.stats_lock:
            self.stats[stat_key] = self.stats.get(stat_key, 0) + increment

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
                    request_hash = hashlib.md5(request_bytes.tostring()).hexdigest()[:8]
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
                # Use special forced analysis that bypasses deduplication
                t = threading.Thread(target=self.analyze_forced, args=(message, url_str, task_id))
                t.setDaemon(True)
                t.start()
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
        if not self.API_KEY:
            self.stderr.println("[!] Claude API key required")
            return False
        
        self.available_models = [
            "claude-3-5-sonnet-20241022",
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229"
        ]
        self.stdout.println("[AI CONNECTION] OK Claude API configured")
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
    
    def print_logo(self):
        self.stdout.println("")
        self.stdout.println("=" * 65)
        self.stdout.println("")
        self.stdout.println("     SILENTCHAIN AI")
        self.stdout.println("     ---------------")
        self.stdout.println("     AI-Powered Security Scanner")
        self.stdout.println("")
        self.stdout.println("     COMMUNITY EDITION v%s" % self.VERSION)
        self.stdout.println("")
        self.stdout.println("     Intelligent | Silent | Adaptive | Comprehensive")
        self.stdout.println("")
        self.stdout.println("     Upgrade to Professional for Active Testing")
        self.stdout.println("     https://silentchain.ai")
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
        t = threading.Thread(target=self.analyze, args=(baseRequestResponse, url_str, task_id))
        t.setDaemon(True)
        t.start()
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
        t = threading.Thread(target=self.analyze, args=(messageInfo, url_str, task_id))
        t.setDaemon(True)
        t.start()

    def analyze(self, messageInfo, url_str=None, task_id=None):
        with self.semaphore:
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
                time.sleep(4)
                self.refreshUI()
    
    def analyze_forced(self, messageInfo, url_str=None, task_id=None):
        """
        Forced analysis that bypasses deduplication.
        Used for context menu re-analysis of already-analyzed requests.
        """
        with self.semaphore:
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
                time.sleep(4)
                self.refreshUI()

    def _get_url_hash(self, url, params):
        param_names = sorted([p.getName() for p in params])
        normalized = str(url).split('?')[0] + '|' + '|'.join(param_names)
        return hashlib.md5(normalized.encode('utf-8')).hexdigest()

    def _get_finding_hash(self, url, title, cwe, param_name=""):
        key = "%s|%s|%s|%s" % (str(url).split('?')[0], title.lower().strip(), cwe, param_name)
        return hashlib.md5(key.encode('utf-8')).hexdigest()

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
                # Use Burp's helper for safe string conversion
                res_body = self.helpers.bytesToString(response_bytes[res.getBodyOffset():])[:3000]
            except Exception as e:
                if self.VERBOSE:
                    self.stdout.println("[DEBUG] Response body decode error: %s" % e)
                res_body = "[Binary/non-UTF8 content]"
            
            res_headers = [str(h) for h in res.getHeaders()[:10]]

            params_sample = [{"name": p.getName(), "value": p.getValue()[:150], 
                            "type": str(p.getType())} for p in params[:5]]

            data = {
                "url": url, "method": req.getMethod(), "status": res.getStatusCode(),
                "mime_type": res.getStatedMimeType(), "params_count": len(params),
                "params_sample": params_sample, "request_headers": req_headers,
                "request_body": req_body, "response_headers": res_headers,
                "response_body": res_body
            }

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
            
            if ai_text.startswith("```"):
                import re
                ai_text = re.sub(r'^```(?:json)?\n?|```$', '', ai_text, flags=re.MULTILINE).strip()
            
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
            except ValueError as e:
                self.stderr.println("[!] JSON parse error: %s" % e)
                self.stderr.println("[!] Attempting to repair malformed JSON...")
                
                # Try multiple repair strategies
                repaired = False
                
                try:
                    import re
                    original_text = ai_text
                    
                    # Strategy 1: Fix unterminated strings by adding closing quotes
                    lines = ai_text.split('\n')
                    fixed_lines = []
                    for line in lines:
                        # Skip empty lines
                        if not line.strip():
                            fixed_lines.append(line)
                            continue
                        
                        # Count unescaped quotes
                        quote_positions = []
                        i = 0
                        while i < len(line):
                            if line[i] == '"' and (i == 0 or line[i-1] != '\\'):
                                quote_positions.append(i)
                            i += 1
                        
                        # If odd number of quotes, try to fix
                        if len(quote_positions) % 2 == 1:
                            # Add closing quote before trailing comma/bracket/brace
                            line = line.rstrip()
                            if line.endswith(',') or line.endswith('}') or line.endswith(']'):
                                line = line[:-1] + '"' + line[-1]
                            elif not line.endswith('"'):
                                line = line + '"'
                        
                        fixed_lines.append(line)
                    
                    ai_text = '\n'.join(fixed_lines)
                    
                    # Strategy 2: Remove trailing commas
                    ai_text = re.sub(r',(\s*[}\]])', r'\1', ai_text)
                    
                    # Strategy 3: Ensure valid array structure
                    ai_text = ai_text.strip()
                    if not ai_text.startswith('['):
                        if ai_text.startswith('{'):
                            ai_text = '[' + ai_text
                        else:
                            # Find first {
                            start_obj = ai_text.find('{')
                            if start_obj != -1:
                                ai_text = '[' + ai_text[start_obj:]
                    
                    if not ai_text.endswith(']'):
                        if ai_text.endswith('}'):
                            ai_text = ai_text + ']'
                        else:
                            # Find last }
                            end_obj = ai_text.rfind('}')
                            if end_obj != -1:
                                ai_text = ai_text[:end_obj+1] + ']'
                    
                    # Strategy 4: Remove any garbage after final ]
                    final_bracket = ai_text.rfind(']')
                    if final_bracket != -1 and final_bracket < len(ai_text) - 1:
                        ai_text = ai_text[:final_bracket + 1]
                    
                    # Try parsing repaired JSON
                    findings = json.loads(ai_text)
                    repaired = True
                    self.stdout.println("[+] JSON successfully repaired")
                    
                except Exception as repair_error:
                    self.stderr.println("[!] JSON repair failed: %s" % repair_error)
                
                if not repaired:
                    # Last resort: try to extract any valid JSON objects
                    self.stderr.println("[!] Attempting last-resort JSON extraction...")
                    try:
                        import re
                        # Find all {...} objects
                        objects = re.findall(r'\{[^}]+\}', original_text, re.DOTALL)
                        if objects:
                            # Try each object
                            findings = []
                            for obj_str in objects[:5]:  # Limit to first 5
                                try:
                                    obj = json.loads(obj_str)
                                    findings.append(obj)
                                except:
                                    pass
                            
                            if findings:
                                self.stdout.println("[+] Extracted %d valid objects from malformed JSON" % len(findings))
                                repaired = True
                    except:
                        pass
                
                if not repaired:
                    self.stderr.println("[!] All repair attempts failed - skipping this analysis")
                    self.stderr.println("[!] AI response was too malformed to parse")
                    if self.VERBOSE:
                        self.stderr.println("[DEBUG] Failed response (first 1000 chars):")
                        self.stderr.println(original_text[:1000])
                    if task_id is not None:
                        self.updateTask(task_id, "Error (JSON Parse Failed)")
                    self.updateStats("errors")
                    return
            
            if not isinstance(findings, list):
                findings = [findings]

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
                
                detail_parts.append("<br><br><b>Community Edition Note:</b><br>")
                detail_parts.append("<i>This finding was detected through passive AI analysis. ")
                detail_parts.append("For active verification with exploit payloads, ")
                detail_parts.append("upgrade to SILENTCHAIN Professional Edition.</i><br>")
                detail_parts.append("<a href='https://silentchain.ai'>Learn More</a>")
                
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
            "Analyze for OWASP Top 10, CWE.\n"
            "Categories: Injection, XSS, Auth, Access Control, Misconfiguration.\n"
            "Format: {\"title\":\"name\",\"severity\":\"High|Medium|Low|Information\","
            "\"confidence\":50-100,\"detail\":\"desc\",\"cwe\":\"CWE-X\","
            "\"owasp\":\"A0X:2021\",\"remediation\":\"fix\"}\n"
            "Data:\n%s\n"
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
