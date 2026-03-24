# -*- coding: utf-8 -*-
# Burp Suite Python Extension: SILENTCHAIN AI - COMMUNITY EDITION
# Version: 2.1.0
# Enhanced Edition: Full Vulnerability Detail Panel + Exploitation + PoC + Scope Manager
# License: MIT License

from burp import IBurpExtender, IHttpListener, IScannerCheck, IScanIssue, ITab, IContextMenuFactory
from java.io import PrintWriter
from java.awt import (BorderLayout, GridBagLayout, GridBagConstraints, Insets,
                      Dimension, Font, Color, FlowLayout, Cursor)
from java.awt.event import MouseAdapter
from javax.swing import (JPanel, JScrollPane, JTextArea, JTable, JLabel, JSplitPane,
                         BorderFactory, SwingUtilities, JButton, BoxLayout, Box,
                         JMenuItem, JTextPane, JTabbedPane, UIManager, SwingConstants,
                         JEditorPane)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.text import SimpleAttributeSet, StyleConstants
from javax.swing.border import EmptyBorder
from java.lang import Runnable
from java.util import ArrayList
from java.util.concurrent import Executors
import json
import threading
import urllib2
import urllib
import time
import hashlib
from datetime import datetime

# ─────────────────────────────────────────────
#  DESIGN TOKENS  (change once → applies everywhere)
# ─────────────────────────────────────────────
class Theme:
    # Primary palette — dark terminal aesthetic
    BG_DARKEST   = Color(0x0D, 0x11, 0x17)   # near-black
    BG_DARK      = Color(0x13, 0x19, 0x22)   # panel bg
    BG_MID       = Color(0x1C, 0x24, 0x30)   # card bg
    BG_LIGHT     = Color(0x24, 0x30, 0x3E)   # hover / selected
    BORDER       = Color(0x2E, 0x3D, 0x4F)   # subtle border

    # Accent — electric cyan
    ACCENT       = Color(0x00, 0xD4, 0xFF)
    ACCENT_DIM   = Color(0x00, 0x7A, 0x99)

    # Text
    TEXT_PRIMARY = Color(0xE2, 0xE8, 0xF0)
    TEXT_MUTED   = Color(0x64, 0x74, 0x8B)
    TEXT_CODE    = Color(0x7D, 0xD3, 0xFC)

    # Severity
    SEV_CRITICAL = Color(0xFF, 0x17, 0x44)
    SEV_HIGH     = Color(0xFF, 0x45, 0x00)
    SEV_MED      = Color(0xFF, 0xA5, 0x00)
    SEV_LOW      = Color(0xFF, 0xD7, 0x00)
    SEV_INFO     = Color(0x38, 0xBD, 0xF8)

    # Confidence
    CONF_CERTAIN   = Color(0x10, 0xB9, 0x81)
    CONF_FIRM      = Color(0x38, 0xBD, 0xF8)
    CONF_TENTATIVE = Color(0xFF, 0xA5, 0x00)

    FONT_MONO  = Font("Monospaced", Font.PLAIN, 12)
    FONT_MONO_B= Font("Monospaced", Font.BOLD, 12)
    FONT_MONO_L= Font("Monospaced", Font.PLAIN, 11)
    FONT_HEAD  = Font("Monospaced", Font.BOLD, 14)
    FONT_TITLE = Font("Monospaced", Font.BOLD, 16)


VALID_SEVERITIES = {
    "high": "High", "medium": "Medium", "low": "Low",
    "information": "Information", "informational": "Information",
    "info": "Information", "inform": "Information",
    "critical": "High"
}

def map_confidence(v):
    try: v = int(v)
    except: v = 50
    if v < 50:  return None
    if v < 75:  return "Tentative"
    if v < 90:  return "Firm"
    return "Certain"

def severity_color(sev):
    return {
        "High":        Theme.SEV_HIGH,
        "Medium":      Theme.SEV_MED,
        "Low":         Theme.SEV_LOW,
        "Information": Theme.SEV_INFO,
    }.get(sev, Theme.TEXT_MUTED)

def confidence_color(conf):
    return {
        "Certain":   Theme.CONF_CERTAIN,
        "Firm":      Theme.CONF_FIRM,
        "Tentative": Theme.CONF_TENTATIVE,
    }.get(conf, Theme.TEXT_MUTED)


# ─────────────────────────────────────────────
#  HELPER: apply dark bg/fg recursively
# ─────────────────────────────────────────────
def dark(component, bg=None, fg=None):
    bg = bg or Theme.BG_DARK
    fg = fg or Theme.TEXT_PRIMARY
    try:
        component.setBackground(bg)
        component.setForeground(fg)
        component.setOpaque(True)
    except: pass
    return component

def styled_btn(text, bg, fg=Color.WHITE, action=None):
    btn = JButton(text)
    btn.setBackground(bg)
    btn.setForeground(fg)
    btn.setFont(Theme.FONT_MONO_B)
    btn.setOpaque(True)
    btn.setBorderPainted(False)
    btn.setFocusPainted(False)
    btn.setCursor(Cursor(Cursor.HAND_CURSOR))
    if action:
        btn.addActionListener(action)
    return btn

def titled_panel(title, layout=None):
    p = JPanel(layout or BorderLayout())
    p.setBackground(Theme.BG_MID)
    border = BorderFactory.createCompoundBorder(
        BorderFactory.createLineBorder(Theme.BORDER, 1),
        BorderFactory.createEmptyBorder(4, 6, 4, 6)
    )
    titled = BorderFactory.createTitledBorder(
        border, title,
        0, 0,
        Theme.FONT_MONO_B, Theme.ACCENT
    )
    p.setBorder(titled)
    return p


# ─────────────────────────────────────────────
#  CONSOLE WRITER
# ─────────────────────────────────────────────
class ConsolePrintWriter:
    def __init__(self, original_writer, extender_ref):
        self.original = original_writer
        self.extender = extender_ref

    def println(self, message):
        self.original.println(message)
        if hasattr(self.extender, 'log_to_console'):
            try: self.extender.log_to_console(str(message))
            except: pass

    def print_(self, m): self.original.print_(m)
    def write(self, d):  self.original.write(d)
    def flush(self):     self.original.flush()


# ─────────────────────────────────────────────
#  THREAD POOL TASK WRAPPERS
# ─────────────────────────────────────────────
class AnalyzeTask(Runnable):
    def __init__(self, extender, messageInfo, url_str, task_id, forced=False):
        self.extender    = extender
        self.messageInfo = messageInfo
        self.url_str     = url_str
        self.task_id     = task_id
        self.forced      = forced

    def run(self):
        if self.forced:
            self.extender.analyze_forced(self.messageInfo, self.url_str, self.task_id)
        else:
            self.extender.analyze(self.messageInfo, self.url_str, self.task_id)


# ─────────────────────────────────────────────
#  CELL RENDERERS
# ─────────────────────────────────────────────
class DarkCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, sel, focus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, sel, focus, row, col)
        c.setBackground(Theme.BG_LIGHT if sel else (Theme.BG_MID if row % 2 == 0 else Theme.BG_DARK))
        c.setForeground(Theme.TEXT_PRIMARY)
        c.setFont(Theme.FONT_MONO_L)
        c.setBorder(EmptyBorder(2, 6, 2, 6))
        return c

class StatusRenderer(DarkCellRenderer):
    COLORS = {
        "Cancelled":  Theme.SEV_CRITICAL,
        "Paused":     Theme.SEV_LOW,
        "Error":      Theme.SEV_HIGH,
        "Skipped":    Theme.SEV_MED,
        "Completed":  Theme.CONF_CERTAIN,
        "Analyzing":  Theme.ACCENT,
        "Waiting":    Theme.ACCENT_DIM,
        "Queued":     Theme.TEXT_MUTED,
    }
    def getTableCellRendererComponent(self, table, value, sel, focus, row, col):
        c = DarkCellRenderer.getTableCellRendererComponent(self, table, value, sel, focus, row, col)
        if value:
            for k, color in self.COLORS.items():
                if k in str(value):
                    c.setForeground(color)
                    c.setFont(Theme.FONT_MONO_B)
                    break
        return c

class SeverityRenderer(DarkCellRenderer):
    def getTableCellRendererComponent(self, table, value, sel, focus, row, col):
        c = DarkCellRenderer.getTableCellRendererComponent(self, table, value, sel, focus, row, col)
        if value:
            sev = str(value)
            color = severity_color(sev)
            c.setForeground(color)
            c.setFont(Theme.FONT_MONO_B)
        return c

class ConfidenceRenderer(DarkCellRenderer):
    def getTableCellRendererComponent(self, table, value, sel, focus, row, col):
        c = DarkCellRenderer.getTableCellRendererComponent(self, table, value, sel, focus, row, col)
        if value:
            c.setForeground(confidence_color(str(value)))
            c.setFont(Theme.FONT_MONO_B)
        return c


# ─────────────────────────────────────────────
#  VULN DETAIL PANEL  ← new core component
# ─────────────────────────────────────────────
class VulnDetailPanel(JPanel):
    """
    Tabbed detail view shown when a finding row is selected.
    Tabs: Overview | Exploitation | PoC | Remediation | Raw JSON
    """
    def __init__(self):
        JPanel.__init__(self, BorderLayout())
        self.setBackground(Theme.BG_DARKEST)
        self._current_finding = None
        self._build_ui()

    def _build_ui(self):
        # Header bar
        self.header = JPanel(BorderLayout())
        self.header.setBackground(Theme.BG_MID)
        self.header.setBorder(EmptyBorder(8, 12, 8, 12))

        self.title_label = JLabel("Select a finding to view details")
        self.title_label.setFont(Theme.FONT_HEAD)
        self.title_label.setForeground(Theme.TEXT_PRIMARY)

        self.severity_badge = JLabel("")
        self.severity_badge.setFont(Theme.FONT_MONO_B)
        self.severity_badge.setHorizontalAlignment(SwingConstants.RIGHT)

        self.header.add(self.title_label, BorderLayout.CENTER)
        self.header.add(self.severity_badge, BorderLayout.EAST)
        self.add(self.header, BorderLayout.NORTH)

        # Tabs
        self.tabs = JTabbedPane()
        self.tabs.setBackground(Theme.BG_DARK)
        self.tabs.setForeground(Theme.TEXT_PRIMARY)
        self.tabs.setFont(Theme.FONT_MONO_B)

        self.overview_pane     = self._make_html_pane()
        self.exploit_pane      = self._make_html_pane()
        self.poc_pane          = self._make_code_pane()
        self.remediation_pane  = self._make_html_pane()
        self.raw_pane          = self._make_code_pane()

        self.tabs.addTab("Overview",      JScrollPane(self.overview_pane))
        self.tabs.addTab("Exploitation",  JScrollPane(self.exploit_pane))
        self.tabs.addTab("PoC Template",  JScrollPane(self.poc_pane))
        self.tabs.addTab("Remediation",   JScrollPane(self.remediation_pane))
        self.tabs.addTab("Raw JSON",      JScrollPane(self.raw_pane))

        # Style tab scrollpanes
        for i in range(self.tabs.getTabCount()):
            sp = self.tabs.getComponentAt(i)
            if isinstance(sp, JScrollPane):
                sp.setBackground(Theme.BG_DARK)
                sp.getViewport().setBackground(Theme.BG_DARK)

        self.add(self.tabs, BorderLayout.CENTER)

        # Empty state message
        self.empty_label = JLabel("← Click any finding row to see full details, exploitation paths and PoC",
                                   SwingConstants.CENTER)
        self.empty_label.setFont(Theme.FONT_MONO)
        self.empty_label.setForeground(Theme.TEXT_MUTED)

        self._show_empty()

    def _make_html_pane(self):
        pane = JEditorPane("text/html", "")
        pane.setEditable(False)
        pane.setBackground(Theme.BG_DARK)
        pane.setForeground(Theme.TEXT_PRIMARY)
        pane.setFont(Theme.FONT_MONO)
        pane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, True)
        return pane

    def _make_code_pane(self):
        area = JTextArea()
        area.setEditable(False)
        area.setBackground(Theme.BG_DARKEST)
        area.setForeground(Theme.TEXT_CODE)
        area.setFont(Theme.FONT_MONO)
        area.setLineWrap(True)
        area.setWrapStyleWord(False)
        area.setBorder(EmptyBorder(8, 10, 8, 10))
        return area

    def _show_empty(self):
        self.title_label.setText("Select a finding to view details")
        self.severity_badge.setText("")
        for pane in [self.overview_pane, self.exploit_pane, self.remediation_pane]:
            pane.setText("")
        for area in [self.poc_pane, self.raw_pane]:
            area.setText("")

    def _css(self):
        return """
        <style>
          body {
            background:#13192200;
            color:#E2E8F0;
            font-family:Monospaced,monospace;
            font-size:12px;
            margin:12px 16px;
            line-height:1.7;
          }
          h3 { color:#00D4FF; margin:16px 0 6px; font-size:13px; border-bottom:1px solid #2E3D4F; padding-bottom:4px; }
          h4 { color:#94A3B8; margin:12px 0 4px; font-size:12px; }
          code, pre {
            background:#0D1117;
            color:#7DD3FC;
            padding:2px 6px;
            border-radius:3px;
            font-family:Monospaced,monospace;
          }
          pre { display:block; padding:10px 14px; margin:8px 0; white-space:pre-wrap; }
          .badge {
            display:inline-block;
            padding:2px 8px;
            border-radius:3px;
            font-weight:bold;
            font-size:11px;
          }
          .high   { background:#FF4500; color:#fff; }
          .medium { background:#FFA500; color:#000; }
          .low    { background:#FFD700; color:#000; }
          .info   { background:#38BDF8; color:#000; }
          .tag {
            display:inline-block;
            background:#1C2430;
            border:1px solid #2E3D4F;
            color:#94A3B8;
            padding:1px 6px;
            border-radius:2px;
            margin:2px;
            font-size:11px;
          }
          .section { margin-bottom:16px; }
          a { color:#00D4FF; }
          ul { margin:6px 0; padding-left:20px; }
          li { margin:3px 0; }
          .warn { color:#FFA500; }
          .ok   { color:#10B981; }
          .critical { color:#FF1744; font-weight:bold; }
        </style>
        """

    def load_finding(self, finding):
        """Called when a row is selected in the findings table."""
        self._current_finding = finding
        self._render_finding(finding)

    def _render_finding(self, f):
        title    = f.get("title", "Unknown Finding")
        severity = f.get("severity", "Information")
        conf     = f.get("confidence", "")
        url      = f.get("url", "")
        detail   = f.get("detail", "")
        cwe      = f.get("cwe", "")
        owasp    = f.get("owasp", "")
        remediation = f.get("remediation", "")
        evidence = f.get("evidence", "")
        exploit_path  = f.get("exploit_path", "")
        exploit_steps = f.get("exploit_steps", [])
        poc_template  = f.get("poc_template", "")
        poc_curl      = f.get("poc_curl", "")
        poc_python    = f.get("poc_python", "")
        affected_params = f.get("affected_params", [])
        business_impact = f.get("business_impact", "")
        cvss          = f.get("cvss_score", "")
        references    = f.get("references", [])

        sev_cls = severity.lower() if severity.lower() in ["high","medium","low"] else "info"

        # ── Header ──
        self.title_label.setText(title)
        badge_text = severity
        if cvss:
            badge_text += "  CVSS: %s" % cvss
        self.severity_badge.setText(badge_text)
        self.severity_badge.setForeground(severity_color(severity))

        # ── Overview Tab ──
        sev_html = '<span class="badge %s">%s</span>' % (sev_cls, severity)
        conf_html = '<span style="color:#10B981">%s</span>' % conf if conf else ""

        params_html = ""
        if affected_params:
            params_html = "".join(['<span class="tag">%s</span>' % p for p in affected_params])
        elif f.get("param"):
            params_html = '<span class="tag">%s</span>' % f.get("param")

        cwe_html = ""
        if cwe:
            cwe_id = cwe.replace("CWE-", "")
            cwe_html = '<a href="https://cwe.mitre.org/data/definitions/%s.html">%s</a>' % (cwe_id, cwe)

        refs_html = ""
        if references:
            refs_html = "<h3>References</h3><ul>"
            for ref in references[:5]:
                refs_html += '<li><a href="%s">%s</a></li>' % (ref, ref[:80])
            refs_html += "</ul>"

        evidence_html = ""
        if evidence:
            evidence_html = "<h3>Evidence</h3><pre>%s</pre>" % evidence[:1000]

        overview = """<html><head>{css}</head><body>
        <div class="section">
          <h3>Finding Summary</h3>
          <table style="width:100%;border-collapse:collapse;">
            <tr><td style="color:#64748B;width:120px">Severity:</td><td>{sev}</td></tr>
            <tr><td style="color:#64748B">Confidence:</td><td>{conf}</td></tr>
            <tr><td style="color:#64748B">URL:</td><td><code>{url}</code></td></tr>
            {cwe_row}
            {owasp_row}
            {cvss_row}
          </table>
        </div>
        <div class="section">
          <h3>Description</h3>
          <p>{detail}</p>
        </div>
        {params_section}
        {evidence_html}
        {refs_html}
        </body></html>""".format(
            css=self._css(),
            sev=sev_html,
            conf=conf_html,
            url=url[:120],
            cwe_row='<tr><td style="color:#64748B">CWE:</td><td>%s</td></tr>' % cwe_html if cwe else "",
            owasp_row='<tr><td style="color:#64748B">OWASP:</td><td>%s</td></tr>' % owasp if owasp else "",
            cvss_row='<tr><td style="color:#64748B">CVSS:</td><td><span class="critical">%s</span></td></tr>' % cvss if cvss else "",
            detail=detail,
            params_section="<h3>Affected Parameters</h3><p>%s</p>" % params_html if params_html else "",
            evidence_html=evidence_html,
            refs_html=refs_html
        )
        self.overview_pane.setText(overview)
        self.overview_pane.setCaretPosition(0)

        # ── Exploitation Tab ──
        steps_html = ""
        if exploit_steps and isinstance(exploit_steps, list):
            steps_html = "<h3>Step-by-Step Exploitation</h3><ol style='margin:6px 0;padding-left:20px'>"
            for i, step in enumerate(exploit_steps):
                steps_html += "<li style='margin:6px 0'>%s</li>" % step
            steps_html += "</ol>"

        impact_html = ""
        if business_impact:
            impact_html = "<h3>Business Impact</h3><p class='warn'>%s</p>" % business_impact

        exploit_html = """<html><head>{css}</head><body>
        <div class="section">
          <h3>Attack Vector</h3>
          <p>{exploit_path}</p>
        </div>
        {steps_html}
        {impact_html}
        <div class="section">
          <h3>Exploitation Prerequisites</h3>
          <ul>
            <li>Access to target application (authenticated or unauthenticated depending on vuln type)</li>
            <li>Ability to intercept/modify HTTP requests (Burp Suite proxy)</li>
            {extra_prereqs}
          </ul>
        </div>
        </body></html>""".format(
            css=self._css(),
            exploit_path=exploit_path or "<span class='warn'>No exploitation path provided by AI — re-analyze with context menu to refresh</span>",
            steps_html=steps_html,
            impact_html=impact_html,
            extra_prereqs="<li>Valid session token / API key (if endpoint is authenticated)</li>" if "auth" in title.lower() or "idor" in title.lower() else ""
        )
        self.exploit_pane.setText(exploit_html)
        self.exploit_pane.setCaretPosition(0)

        # ── PoC Tab ──
        poc_parts = []
        if poc_curl:
            poc_parts.append("# ── cURL PoC ──\n%s" % poc_curl)
        if poc_python:
            poc_parts.append("# ── Python PoC ──\n%s" % poc_python)
        if poc_template and not poc_curl and not poc_python:
            poc_parts.append("# ── PoC Template ──\n%s" % poc_template)
        if not poc_parts:
            poc_parts.append("# No PoC generated yet.\n# Right-click the request in Burp → Analyze Request\n# to trigger a fresh AI analysis with PoC generation.")

        self.poc_pane.setText("\n\n".join(poc_parts))
        self.poc_pane.setCaretPosition(0)

        # ── Remediation Tab ──
        rem_html = """<html><head>{css}</head><body>
        <div class="section">
          <h3>Remediation</h3>
          <p>{remediation}</p>
        </div>
        <div class="section">
          <h3>Verification Steps</h3>
          <ol>
            <li>Apply the fix in a development environment</li>
            <li>Re-run the same request via Burp → Analyze Request</li>
            <li>Confirm the AI no longer flags the vulnerability</li>
            <li>Run a full regression test on the affected endpoint</li>
          </ol>
        </div>
        <div class="section">
          <h3>Secure Code Reference</h3>
          <p>See <a href="https://cheatsheetseries.owasp.org">OWASP Cheat Sheet Series</a>
          for language-specific secure coding guidance related to {owasp}.</p>
        </div>
        </body></html>""".format(
            css=self._css(),
            remediation=remediation or "No remediation provided — re-analyze to refresh.",
            owasp=owasp or "this vulnerability class"
        )
        self.remediation_pane.setText(rem_html)
        self.remediation_pane.setCaretPosition(0)

        # ── Raw JSON Tab ──
        self.raw_pane.setText(json.dumps(f, indent=2))
        self.raw_pane.setCaretPosition(0)


# ─────────────────────────────────────────────
#  CUSTOM SCAN ISSUE
# ─────────────────────────────────────────────
class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, messages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url         = url
        self._messages    = messages
        self._name        = name
        self._detail      = detail
        self._severity    = severity
        self._confidence  = confidence

    def getUrl(self):               return self._url
    def getIssueName(self):         return self._name
    def getIssueType(self):         return 0x80000003
    def getSeverity(self):          return self._severity
    def getConfidence(self):        return self._confidence
    def getIssueDetail(self):       return self._detail
    def getHttpMessages(self):      return self._messages
    def getHttpService(self):       return self._httpService
    def getIssueBackground(self):   return None
    def getRemediationBackground(self): return None
    def getRemediationDetail(self): return None


# ─────────────────────────────────────────────
#  MAIN EXTENDER
# ─────────────────────────────────────────────
class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers   = callbacks.getHelpers()

        orig_out = PrintWriter(callbacks.getStdout(), True)
        orig_err = PrintWriter(callbacks.getStderr(), True)
        self.stdout = ConsolePrintWriter(orig_out, self)
        self.stderr = ConsolePrintWriter(orig_err, self)

        self.VERSION      = "2.0.0"
        self.EDITION      = "Community"
        self.RELEASE_DATE = "2026-03-23"
        self.CONFIG_VERSION = 3

        callbacks.setExtensionName("SILENTCHAIN AI - %s v%s" % (self.EDITION, self.VERSION))
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)

        import os
        self.config_file     = os.path.join(os.path.expanduser("~"), ".silentchain_config.json")
        self.vuln_cache_file = os.path.join(os.path.expanduser("~"), ".silentchain_vuln_cache.json")

        # Defaults
        self.AI_PROVIDER           = "Ollama"
        self.API_URL               = "http://localhost:11434"
        self.API_KEY               = ""
        self.MODEL                 = "deepseek-r1:latest"
        self.AZURE_API_VERSION     = "2024-06-01"
        self.MAX_TOKENS            = 3072    # increased for richer PoC output
        self.AI_REQUEST_TIMEOUT    = 60
        self.available_models      = []
        self.VERBOSE               = True
        self.THEME                 = "Dark"
        self.PASSIVE_SCANNING_ENABLED = True
        self.SKIP_EXTENSIONS       = ["js","gif","jpg","png","ico","css","woff","woff2","ttf","svg"]

        self.load_config()
        self.apply_environment_config()

        # UI refresh state
        self._ui_dirty       = True
        self._refresh_pending= False
        self._last_console_len = 0
        self._cache_dirty    = False

        # Data stores
        self.console_messages = []
        self.console_lock     = threading.Lock()
        self.max_console_messages = 1000

        self.findings_list    = []       # full rich dicts (includes exploit/poc data)
        self.findings_lock_ui = threading.Lock()
        self.findings_cache   = {}
        self.findings_lock    = threading.Lock()

        self.vuln_cache       = {}
        self.vuln_cache_lock  = threading.Lock()

        self.context_menu_last_invoke  = {}
        self.context_menu_debounce_time= 1.0
        self.context_menu_lock         = threading.Lock()

        self.processed_urls = set()
        self.url_lock       = threading.Lock()

        self.host_semaphores     = {}
        self.host_semaphore_lock = threading.Lock()
        self.global_semaphore    = threading.Semaphore(5)

        self.thread_pool = Executors.newFixedThreadPool(5)

        # Scope management (custom target list)
        self.scope_entries = []  # list of {"url": "https://example.com", "enabled": True}
        self.scope_lock = threading.Lock()
        self.scope_file = os.path.join(os.path.expanduser("~"), ".silentchain_scope.json")

        self.last_request_time = 0
        self.min_delay         = 4.0

        self.tasks      = []
        self.tasks_lock = threading.Lock()
        self.stats      = {k: 0 for k in [
            "total_requests","analyzed","cached_reused","skipped_duplicate",
            "skipped_rate_limit","skipped_low_confidence","findings_created","errors"
        ]}
        self.stats_lock = threading.Lock()

        self.initUI()
        self.load_vuln_cache()
        self.load_scope()
        self.log_to_console("=== SILENTCHAIN AI v%s initialized ===" % self.VERSION)
        self.refreshUI()
        self.print_logo()

        def _conn_test():
            if not self.test_ai_connection():
                self.stderr.println("[!] AI connection failed — check Settings")
        t = threading.Thread(target=_conn_test)
        t.setDaemon(True)
        t.start()

        callbacks.addSuiteTab(self)
        self.start_auto_refresh_timer()

    # ─────────────────────────
    #  UI CONSTRUCTION
    # ─────────────────────────
    def initUI(self):
        self.panel = JPanel(BorderLayout())
        self.panel.setBackground(Theme.BG_DARKEST)

        # ── TOP BAR ──
        topBar = JPanel(BorderLayout())
        topBar.setBackground(Theme.BG_MID)
        topBar.setBorder(EmptyBorder(8, 14, 8, 14))

        # Title
        titlePanel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        titlePanel.setOpaque(False)
        titleLbl = JLabel("SILENTCHAIN AI")
        titleLbl.setFont(Theme.FONT_TITLE)
        titleLbl.setForeground(Theme.ACCENT)
        versionLbl = JLabel("  v%s  Community Edition" % self.VERSION)
        versionLbl.setFont(Theme.FONT_MONO_L)
        versionLbl.setForeground(Theme.TEXT_MUTED)
        titlePanel.add(titleLbl)
        titlePanel.add(versionLbl)
        topBar.add(titlePanel, BorderLayout.WEST)

        # Status strip (inline)
        statusStrip = JPanel(FlowLayout(FlowLayout.RIGHT, 16, 0))
        statusStrip.setOpaque(False)

        self.providerStatusLabel = JLabel(self.AI_PROVIDER)
        self.modelStatusLabel    = JLabel(self.MODEL)
        self.scanStatusLabel     = JLabel("Enabled" if self.PASSIVE_SCANNING_ENABLED else "Disabled")
        self.cacheStatusLabel    = JLabel("0")

        for lbl, prefix in [
            (self.providerStatusLabel, "Provider: "),
            (self.modelStatusLabel,    "Model: "),
            (self.scanStatusLabel,     "Scan: "),
            (self.cacheStatusLabel,    "Cache: "),
        ]:
            pair = JPanel(FlowLayout(FlowLayout.LEFT, 2, 0))
            pair.setOpaque(False)
            pfx = JLabel(prefix)
            pfx.setFont(Theme.FONT_MONO_L)
            pfx.setForeground(Theme.TEXT_MUTED)
            lbl.setFont(Theme.FONT_MONO_B)
            lbl.setForeground(Theme.ACCENT)
            pair.add(pfx)
            pair.add(lbl)
            statusStrip.add(pair)

        topBar.add(statusStrip, BorderLayout.EAST)
        self.panel.add(topBar, BorderLayout.NORTH)

        # ── STATS BAR ──
        statsBar = JPanel(FlowLayout(FlowLayout.LEFT, 20, 4))
        statsBar.setBackground(Theme.BG_DARK)
        statsBar.setBorder(EmptyBorder(4, 14, 4, 14))

        self.statsLabels = {}
        stat_defs = [
            ("total_requests",       "Requests"),
            ("analyzed",             "Analyzed"),
            ("cached_reused",        "Cached"),
            ("skipped_duplicate",    "Deduped"),
            ("skipped_low_confidence","LowConf"),
            ("findings_created",     "Findings"),
            ("errors",               "Errors"),
        ]
        for key, label in stat_defs:
            pair = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
            pair.setOpaque(False)
            plbl = JLabel(label + ":")
            plbl.setFont(Theme.FONT_MONO_L)
            plbl.setForeground(Theme.TEXT_MUTED)
            vlbl = JLabel("0")
            vlbl.setFont(Theme.FONT_MONO_B)
            vlbl.setForeground(Theme.TEXT_PRIMARY)
            self.statsLabels[key] = vlbl
            pair.add(plbl)
            pair.add(vlbl)
            statsBar.add(pair)

        self.panel.add(statsBar, BorderLayout.AFTER_LAST_LINE)

        # ── BUTTON BAR ──
        btnBar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        btnBar.setBackground(Theme.BG_MID)
        btnBar.setBorder(EmptyBorder(4, 10, 4, 10))

        self.scanningButton = styled_btn("Stop Scanning",    Theme.CONF_CERTAIN,  action=self.toggleScanning)
        self.exportButton   = styled_btn("Export HTML",      Color(0x1E, 0x40, 0xAF), action=self.exportHtmlReport)
        self.exportCsvBtn   = styled_btn("Export CSV",       Color(0x0F, 0x76, 0x6E), action=self.exportFindings)
        self.settingsButton = styled_btn("Settings",         Theme.BG_LIGHT, fg=Theme.TEXT_PRIMARY, action=self.openSettings)
        self.scopeButton    = styled_btn("Scope Manager",    Color(0x7C, 0x3A, 0xED), action=self.openScopeManager)
        self.clearButton    = styled_btn("Clear Done",       Theme.BG_LIGHT, fg=Theme.TEXT_MUTED,   action=self.clearCompleted)
        self.cancelAllBtn   = styled_btn("Cancel All",       Theme.SEV_HIGH,   action=self.cancelAllTasks)

        for b in [self.scanningButton, self.exportButton, self.exportCsvBtn,
                  self.settingsButton, self.scopeButton, self.clearButton, self.cancelAllBtn]:
            btnBar.add(b)

        self._sync_scanning_button()

        # Wrap stats+buttons into a south compound
        southPanel = JPanel(BorderLayout())
        southPanel.setBackground(Theme.BG_DARK)
        southPanel.add(btnBar, BorderLayout.NORTH)
        southPanel.add(statsBar, BorderLayout.SOUTH)
        self.panel.add(southPanel, BorderLayout.SOUTH)

        # ── MAIN SPLIT (horizontal) ──
        # LEFT: tasks + findings stacked
        # RIGHT: vuln detail panel
        mainSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        mainSplit.setBackground(Theme.BG_DARKEST)
        mainSplit.setDividerSize(4)
        mainSplit.setResizeWeight(0.45)

        # LEFT COLUMN: tasks on top, findings on bottom
        leftSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        leftSplit.setBackground(Theme.BG_DARKEST)
        leftSplit.setDividerSize(4)
        leftSplit.setResizeWeight(0.30)

        # Tasks table
        taskPanel = titled_panel("Active Tasks")
        taskPanel.setLayout(BorderLayout())
        self.taskTableModel = DefaultTableModel()
        for col in ["Timestamp", "Type", "URL", "Status", "Duration"]:
            self.taskTableModel.addColumn(col)
        self.taskTable = JTable(self.taskTableModel)
        self._style_table(self.taskTable, [150, 80, 280, 130, 70])
        self.taskTable.getColumnModel().getColumn(3).setCellRenderer(StatusRenderer())
        taskPanel.add(JScrollPane(self.taskTable), BorderLayout.CENTER)
        self._style_scrollpane(JScrollPane(self.taskTable))
        scroll = JScrollPane(self.taskTable)
        self._style_scrollpane(scroll)
        taskPanel.add(scroll, BorderLayout.CENTER)
        leftSplit.setTopComponent(taskPanel)

        # Findings table + stats strip
        findingsOuter = titled_panel("Findings")
        findingsOuter.setLayout(BorderLayout())

        self.findingsStatsLabel = JLabel("Total: 0 | High: 0 | Medium: 0 | Low: 0 | Info: 0")
        self.findingsStatsLabel.setFont(Theme.FONT_MONO_B)
        self.findingsStatsLabel.setForeground(Theme.TEXT_PRIMARY)
        self.findingsStatsLabel.setBorder(EmptyBorder(4, 6, 4, 6))
        findingsOuter.add(self.findingsStatsLabel, BorderLayout.NORTH)

        self.findingsTableModel = DefaultTableModel()
        for col in ["Time", "URL", "Finding", "Severity", "Confidence"]:
            self.findingsTableModel.addColumn(col)
        self.findingsTable = JTable(self.findingsTableModel)
        self._style_table(self.findingsTable, [120, 220, 200, 75, 80])
        self.findingsTable.getColumnModel().getColumn(3).setCellRenderer(SeverityRenderer())
        self.findingsTable.getColumnModel().getColumn(4).setCellRenderer(ConfidenceRenderer())

        # Row selection → populate detail panel
        extender_ref = self
        class RowSelector(MouseAdapter):
            def mouseClicked(self, e):
                row = extender_ref.findingsTable.getSelectedRow()
                if row < 0: return
                model_row = extender_ref.findingsTable.convertRowIndexToModel(row)
                with extender_ref.findings_lock_ui:
                    if model_row < len(extender_ref.findings_list):
                        finding = extender_ref.findings_list[model_row]
                        extender_ref.detail_panel.load_finding(finding)

        self.findingsTable.addMouseListener(RowSelector())

        fscroll = JScrollPane(self.findingsTable)
        self._style_scrollpane(fscroll)
        findingsOuter.add(fscroll, BorderLayout.CENTER)
        leftSplit.setBottomComponent(findingsOuter)

        mainSplit.setLeftComponent(leftSplit)

        # RIGHT COLUMN: tabbed detail panel + console
        rightSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        rightSplit.setBackground(Theme.BG_DARKEST)
        rightSplit.setDividerSize(4)
        rightSplit.setResizeWeight(0.70)

        self.detail_panel = VulnDetailPanel()
        detailWrapper = titled_panel("Vulnerability Detail")
        detailWrapper.setLayout(BorderLayout())
        detailWrapper.add(self.detail_panel, BorderLayout.CENTER)
        rightSplit.setTopComponent(detailWrapper)

        # Console
        consolePanel = titled_panel("Console")
        consolePanel.setLayout(BorderLayout())
        self.consoleTextArea = JTextArea()
        self.consoleTextArea.setEditable(False)
        self.consoleTextArea.setFont(Theme.FONT_MONO_L)
        self.consoleTextArea.setBackground(Theme.BG_DARKEST)
        self.consoleTextArea.setForeground(Theme.TEXT_CODE)
        self.consoleTextArea.setLineWrap(True)
        self.console_user_scrolled = False

        cscroll = JScrollPane(self.consoleTextArea)
        self._style_scrollpane(cscroll)

        from java.awt.event import AdjustmentListener
        class ScrollWatcher(AdjustmentListener):
            def __init__(self, ext): self.ext = ext
            def adjustmentValueChanged(self, e):
                sb = e.getAdjustable()
                at_bottom = sb.getValue() >= sb.getMaximum() - sb.getVisibleAmount() - 10
                self.ext.console_user_scrolled = not at_bottom
        cscroll.getVerticalScrollBar().addAdjustmentListener(ScrollWatcher(self))

        consolePanel.add(cscroll, BorderLayout.CENTER)
        rightSplit.setBottomComponent(consolePanel)

        mainSplit.setRightComponent(rightSplit)
        self.panel.add(mainSplit, BorderLayout.CENTER)

        self.mainSplit = mainSplit
        self.leftSplit = leftSplit
        self.rightSplit = rightSplit

        # Set divider positions after layout
        from java.awt.event import ComponentAdapter
        class Initializer(ComponentAdapter):
            def __init__(self, ext): self.ext = ext; self.done = False
            def componentResized(self, e):
                if self.done or self.ext.panel.getWidth() < 10: return
                self.done = True
                w = self.ext.panel.getWidth()
                h = self.ext.panel.getHeight()
                self.ext.mainSplit.setDividerLocation(int(w * 0.42))
                self.ext.leftSplit.setDividerLocation(int(h * 0.28))
                self.ext.rightSplit.setDividerLocation(int(h * 0.65))
        self.panel.addComponentListener(Initializer(self))

    def _style_table(self, table, col_widths):
        table.setBackground(Theme.BG_DARK)
        table.setForeground(Theme.TEXT_PRIMARY)
        table.setFont(Theme.FONT_MONO_L)
        table.setRowHeight(22)
        table.setShowGrid(False)
        table.setIntercellSpacing(Dimension(0, 1))
        table.setAutoCreateRowSorter(True)
        table.setSelectionBackground(Theme.BG_LIGHT)
        table.setSelectionForeground(Theme.ACCENT)
        table.getTableHeader().setBackground(Theme.BG_MID)
        table.getTableHeader().setForeground(Theme.TEXT_MUTED)
        table.getTableHeader().setFont(Theme.FONT_MONO_B)
        # Default dark renderer for all columns
        dark_r = DarkCellRenderer()
        for i, w in enumerate(col_widths):
            table.getColumnModel().getColumn(i).setPreferredWidth(w)
            table.getColumnModel().getColumn(i).setCellRenderer(dark_r)

    def _style_scrollpane(self, sp):
        sp.setBackground(Theme.BG_DARK)
        sp.getViewport().setBackground(Theme.BG_DARK)
        sp.setBorder(BorderFactory.createLineBorder(Theme.BORDER, 1))
        return sp

    # ─────────────────────────
    #  REFRESH
    # ─────────────────────────
    def refreshUI(self, event=None):
        if self._refresh_pending or not self._ui_dirty:
            return

        class Refresh(Runnable):
            def __init__(self, ext): self.ext = ext
            def run(self):
                try:
                    ext = self.ext
                    with ext.stats_lock:
                        stats = dict(ext.stats)
                    with ext.tasks_lock:
                        tasks_rows = []
                        for t in ext.tasks[-100:]:
                            dur = ""
                            if t.get("end_time"): dur = "%.1fs" % (t["end_time"] - t["start_time"])
                            elif t.get("start_time"): dur = "%.1fs" % (time.time() - t["start_time"])
                            tasks_rows.append([t.get("timestamp",""), t.get("type",""),
                                               t.get("url","")[:90], t.get("status",""), dur])
                    with ext.findings_lock_ui:
                        finds_rows = []
                        counts = {"High":0,"Medium":0,"Low":0,"Information":0}
                        for f in ext.findings_list:
                            sev = f.get("severity","Information")
                            if sev in counts: counts[sev] += 1
                            finds_rows.append([
                                f.get("discovered_at","")[11:],  # time only
                                f.get("url","")[:80],
                                f.get("title","")[:60],
                                sev,
                                f.get("confidence","")
                            ])
                    with ext.console_lock:
                        cur_len = len(ext.console_messages)
                        prev_len = ext._last_console_len
                        new_msgs = list(ext.console_messages[prev_len:]) if cur_len > prev_len else []
                        changed = cur_len != prev_len
                        if cur_len < prev_len:
                            new_msgs = list(ext.console_messages)
                            prev_len = 0
                            changed = True

                    # Stats
                    for k, lbl in ext.statsLabels.items():
                        lbl.setText(str(stats.get(k, 0)))
                        # Color errors red
                        if k == "errors" and stats.get(k, 0) > 0:
                            lbl.setForeground(Theme.SEV_HIGH)
                        elif k == "findings_created" and stats.get(k, 0) > 0:
                            lbl.setForeground(Theme.CONF_CERTAIN)
                        else:
                            lbl.setForeground(Theme.TEXT_PRIMARY)

                    ext.providerStatusLabel.setText(ext.AI_PROVIDER)
                    ext.modelStatusLabel.setText(ext.MODEL[:30])
                    ext.scanStatusLabel.setText("ON" if ext.PASSIVE_SCANNING_ENABLED else "OFF")
                    ext.scanStatusLabel.setForeground(Theme.CONF_CERTAIN if ext.PASSIVE_SCANNING_ENABLED else Theme.SEV_HIGH)
                    with ext.vuln_cache_lock:
                        ext.cacheStatusLabel.setText(str(len(ext.vuln_cache)))

                    ext.update_table_diff(ext.taskTableModel, tasks_rows)
                    ext.update_table_diff(ext.findingsTableModel, finds_rows)

                    total = sum(counts.values())
                    ext.findingsStatsLabel.setText(
                        "Total: %d  |  High: %d  |  Medium: %d  |  Low: %d  |  Info: %d"
                        % (total, counts["High"], counts["Medium"], counts["Low"], counts["Information"])
                    )

                    if changed:
                        if prev_len == 0:
                            ext.consoleTextArea.setText("\n".join(new_msgs))
                        else:
                            doc = ext.consoleTextArea.getDocument()
                            doc.insertString(doc.getLength(), "\n" + "\n".join(new_msgs), None)
                        ext._last_console_len = cur_len
                        if not ext.console_user_scrolled:
                            try:
                                doc = ext.consoleTextArea.getDocument()
                                ext.consoleTextArea.setCaretPosition(doc.getLength())
                            except: pass
                finally:
                    self.ext._refresh_pending = False

        self._ui_dirty = False
        self._refresh_pending = True
        self._async_save_cache()
        SwingUtilities.invokeLater(Refresh(self))

    def update_table_diff(self, model, new_rows):
        cur = model.getRowCount()
        for i, row in enumerate(new_rows):
            if i < cur:
                for j, val in enumerate(row):
                    try:
                        if str(model.getValueAt(i, j)) != str(val):
                            model.setValueAt(val, i, j)
                    except: model.setValueAt(val, i, j)
            else:
                model.addRow(row)
        while model.getRowCount() > len(new_rows):
            model.removeRow(model.getRowCount() - 1)

    def start_auto_refresh_timer(self):
        def loop():
            chk = 0
            while True:
                time.sleep(5)
                self.refreshUI()
                chk += 1
                if chk >= 6:
                    chk = 0
                    self.check_stuck_tasks()
        t = threading.Thread(target=loop)
        t.setDaemon(True)
        t.start()

    def check_stuck_tasks(self):
        now = time.time()
        with self.tasks_lock:
            for i, t in enumerate(self.tasks):
                s = t.get("status","")
                st = t.get("start_time", 0)
                if ("Analyzing" in s or "Waiting" in s) and st > 0:
                    if now - st > 300:
                        self.stderr.println("[AUTO-CHECK] Stuck task %d: %s" % (i, t.get("url","")[:50]))

    # ─────────────────────────
    #  BUTTON HANDLERS
    # ─────────────────────────
    def clearCompleted(self, e):
        with self.tasks_lock:
            self.tasks = [t for t in self.tasks
                          if t.get("status") not in ("Completed",) and
                          "Skipped" not in t.get("status","") and
                          "Error" not in t.get("status","")]
        self.refreshUI()

    def cancelAllTasks(self, e):
        n = 0
        with self.tasks_lock:
            for t in self.tasks:
                if t.get("status") not in ("Completed","Cancelled") and "Error" not in t.get("status",""):
                    t["status"] = "Cancelled"; t["end_time"] = time.time(); n += 1
        self.stdout.println("[CANCEL] Cancelled %d tasks" % n)
        self.refreshUI()

    def toggleScanning(self, e):
        self.PASSIVE_SCANNING_ENABLED = not self.PASSIVE_SCANNING_ENABLED
        self._sync_scanning_button()
        self.save_config()
        self.refreshUI()

    def _sync_scanning_button(self):
        if not hasattr(self, 'scanningButton'): return
        if self.PASSIVE_SCANNING_ENABLED:
            self.scanningButton.setText("Stop Scanning")
            self.scanningButton.setBackground(Theme.CONF_CERTAIN)
        else:
            self.scanningButton.setText("Start Scanning")
            self.scanningButton.setBackground(Theme.SEV_HIGH)

    # ─────────────────────────
    #  EXPORT: HTML REPORT
    # ─────────────────────────
    def exportHtmlReport(self, event):
        with self.findings_lock_ui:
            findings_copy = list(self.findings_list)
        if not findings_copy:
            self.stdout.println("[EXPORT] No findings to export")
            return
        try:
            from javax.swing import JFileChooser
            from java.io import File
            fc = JFileChooser()
            ts = time.strftime("%Y%m%d_%H%M%S")
            fc.setSelectedFile(File("SILENTCHAIN_Report_%s.html" % ts))
            if fc.showSaveDialog(self.panel) != JFileChooser.APPROVE_OPTION:
                return
            path = str(fc.getSelectedFile().getAbsolutePath())
            html = self._build_html_report(findings_copy, ts)
            with open(path, 'w') as f:
                f.write(html)
            self.stdout.println("[EXPORT] HTML report saved: %s (%d findings)" % (path, len(findings_copy)))
        except Exception as e:
            self.stderr.println("[!] Export failed: %s" % e)

    def _build_html_report(self, findings, ts):
        sev_order = {"High":0,"Medium":1,"Low":2,"Information":3}
        findings = sorted(findings, key=lambda f: sev_order.get(f.get("severity","Information"), 4))

        counts = {"High":0,"Medium":0,"Low":0,"Information":0}
        for f in findings:
            s = f.get("severity","Information")
            if s in counts: counts[s] += 1

        cards_html = ""
        for i, f in enumerate(findings):
            sev = f.get("severity","Information")
            sev_cls = sev.lower() if sev.lower() in ["high","medium","low"] else "info"
            exploit_steps = f.get("exploit_steps", [])
            steps_html = ""
            if exploit_steps:
                steps_html = "<ol>" + "".join("<li>%s</li>" % s for s in exploit_steps) + "</ol>"

            poc_html = ""
            if f.get("poc_curl"):
                poc_html += "<h4>cURL</h4><pre>%s</pre>" % f["poc_curl"]
            if f.get("poc_python"):
                poc_html += "<h4>Python</h4><pre>%s</pre>" % f["poc_python"]
            if f.get("poc_template") and not poc_html:
                poc_html = "<pre>%s</pre>" % f["poc_template"]

            cards_html += """
            <div class="card" id="f{idx}">
              <div class="card-header">
                <span class="badge {sev_cls}">{sev}</span>
                <span class="card-title">{title}</span>
                <span class="conf">{conf}</span>
              </div>
              <div class="card-meta">
                <code>{url}</code>
                {cwe_span}
                {owasp_span}
              </div>
              <div class="tabs-container" data-idx="{idx}">
                <div class="tab-btns">
                  <button class="tab-btn active" onclick="showTab({idx},'desc')">Description</button>
                  <button class="tab-btn" onclick="showTab({idx},'exploit')">Exploitation</button>
                  <button class="tab-btn" onclick="showTab({idx},'poc')">PoC</button>
                  <button class="tab-btn" onclick="showTab({idx},'fix')">Remediation</button>
                </div>
                <div id="desc-{idx}" class="tab-pane active">
                  <p>{detail}</p>
                  {evidence}
                  {impact}
                </div>
                <div id="exploit-{idx}" class="tab-pane hidden">
                  <p>{exploit_path}</p>
                  {steps_html}
                </div>
                <div id="poc-{idx}" class="tab-pane hidden">
                  {poc_html}
                </div>
                <div id="fix-{idx}" class="tab-pane hidden">
                  <p>{remediation}</p>
                </div>
              </div>
            </div>""".format(
                idx=i, sev=sev, sev_cls=sev_cls,
                title=f.get("title",""),
                conf=f.get("confidence",""),
                url=f.get("url","")[:120],
                cwe_span='<span class="meta-tag">%s</span>' % f["cwe"] if f.get("cwe") else "",
                owasp_span='<span class="meta-tag">%s</span>' % f["owasp"] if f.get("owasp") else "",
                detail=f.get("detail",""),
                evidence='<div class="evidence"><strong>Evidence:</strong><pre>%s</pre></div>' % f["evidence"] if f.get("evidence") else "",
                impact='<div class="impact"><strong>Business Impact:</strong> %s</div>' % f["business_impact"] if f.get("business_impact") else "",
                exploit_path=f.get("exploit_path","No exploitation path recorded."),
                steps_html=steps_html,
                poc_html=poc_html or "<p>No PoC available. Re-analyze to generate.</p>",
                remediation=f.get("remediation","")
            )

        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SILENTCHAIN AI Report — {ts}</title>
<style>
  :root {{
    --bg: #0D1117; --bg2: #13192A; --bg3: #1C2430;
    --border: #2E3D4F; --accent: #00D4FF; --text: #E2E8F0;
    --muted: #64748B; --code: #7DD3FC;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Courier New', monospace;
          font-size: 13px; line-height: 1.7; padding: 24px; }}
  h1 {{ color: var(--accent); font-size: 22px; margin-bottom: 4px; }}
  h4 {{ color: var(--muted); margin: 12px 0 6px; }}
  .subtitle {{ color: var(--muted); margin-bottom: 24px; }}
  .summary {{
    display: flex; gap: 16px; margin-bottom: 28px; flex-wrap: wrap;
  }}
  .summary-box {{
    background: var(--bg3); border: 1px solid var(--border);
    border-radius: 6px; padding: 14px 20px; min-width: 120px; text-align: center;
  }}
  .summary-box .num {{ font-size: 28px; font-weight: bold; }}
  .summary-box .lbl {{ color: var(--muted); font-size: 11px; margin-top: 2px; }}
  .high-num {{ color: #FF4500; }} .medium-num {{ color: #FFA500; }}
  .low-num  {{ color: #FFD700; }} .info-num  {{ color: #38BDF8; }}
  .card {{
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: 8px; margin-bottom: 16px; overflow: hidden;
  }}
  .card-header {{
    display: flex; align-items: center; gap: 12px;
    padding: 12px 16px; background: var(--bg3);
    border-bottom: 1px solid var(--border);
  }}
  .card-title {{ flex: 1; font-weight: bold; font-size: 14px; }}
  .conf {{ color: var(--muted); font-size: 11px; }}
  .card-meta {{
    padding: 8px 16px; display: flex; gap: 10px; align-items: center;
    flex-wrap: wrap; border-bottom: 1px solid var(--border);
    background: var(--bg); font-size: 11px;
  }}
  .card-meta code {{ color: var(--code); }}
  .meta-tag {{
    background: var(--bg3); border: 1px solid var(--border);
    padding: 1px 6px; border-radius: 3px; color: var(--muted); font-size: 10px;
  }}
  .badge {{
    padding: 2px 10px; border-radius: 3px; font-size: 11px; font-weight: bold;
    white-space: nowrap;
  }}
  .high {{ background: #FF4500; color: #fff; }}
  .medium {{ background: #FFA500; color: #000; }}
  .low {{ background: #FFD700; color: #000; }}
  .info {{ background: #38BDF8; color: #000; }}
  .tab-btns {{
    display: flex; border-bottom: 1px solid var(--border);
    background: var(--bg3);
  }}
  .tab-btn {{
    background: none; border: none; color: var(--muted);
    padding: 8px 16px; cursor: pointer; font-family: inherit; font-size: 12px;
    border-bottom: 2px solid transparent;
  }}
  .tab-btn:hover {{ color: var(--text); }}
  .tab-btn.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
  .tab-pane {{ padding: 16px; }}
  .tab-pane.hidden {{ display: none; }}
  pre {{
    background: var(--bg); color: var(--code);
    padding: 12px 14px; border-radius: 4px; margin: 8px 0;
    white-space: pre-wrap; word-break: break-all;
    border: 1px solid var(--border); font-size: 12px;
  }}
  .evidence {{ margin: 10px 0; padding: 10px; background: var(--bg); border-radius: 4px; }}
  .impact {{ margin: 10px 0; color: #FFA500; }}
  ol {{ margin: 8px 0 8px 20px; }}
  li {{ margin: 4px 0; }}
  a {{ color: var(--accent); }}
  .footer {{ margin-top: 32px; color: var(--muted); font-size: 11px; text-align: center; }}
</style>
</head>
<body>
<h1>SILENTCHAIN AI — Security Report</h1>
<p class="subtitle">Generated: {ts} &nbsp;|&nbsp; Model: {model} &nbsp;|&nbsp; Community Edition</p>
<div class="summary">
  <div class="summary-box"><div class="num">{total}</div><div class="lbl">Total</div></div>
  <div class="summary-box"><div class="num high-num">{high}</div><div class="lbl">High</div></div>
  <div class="summary-box"><div class="num medium-num">{med}</div><div class="lbl">Medium</div></div>
  <div class="summary-box"><div class="num low-num">{low}</div><div class="lbl">Low</div></div>
  <div class="summary-box"><div class="num info-num">{info}</div><div class="lbl">Info</div></div>
</div>
{cards}
<div class="footer">SILENTCHAIN AI Community Edition — silentchain.ai</div>
<script>
function showTab(idx, name) {{
  var c = document.querySelector('[data-idx="'+idx+'"]');
  c.querySelectorAll('.tab-pane').forEach(p => p.classList.add('hidden'));
  c.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(name+'-'+idx).classList.remove('hidden');
  event.target.classList.add('active');
}}
</script>
</body></html>""".format(
            ts=ts, model=self.MODEL, cards=cards_html,
            total=len(findings),
            high=counts["High"], med=counts["Medium"],
            low=counts["Low"], info=counts["Information"]
        )

    # ─────────────────────────
    #  EXPORT: CSV (kept)
    # ─────────────────────────
    def exportFindings(self, event):
        if self.findingsTableModel.getRowCount() == 0:
            self.stdout.println("[EXPORT] No findings"); return
        try:
            from javax.swing import JFileChooser
            from java.io import File
            fc = JFileChooser()
            fc.setSelectedFile(File("SILENTCHAIN_%s.csv" % time.strftime("%Y%m%d_%H%M%S")))
            if fc.showSaveDialog(self.panel) != JFileChooser.APPROVE_OPTION: return
            path = str(fc.getSelectedFile().getAbsolutePath())
            with open(path, 'w') as f:
                headers = [self.findingsTableModel.getColumnName(c)
                           for c in range(self.findingsTableModel.getColumnCount())]
                f.write(','.join(['"'+h+'"' for h in headers]) + '\n')
                for r in range(self.findingsTableModel.getRowCount()):
                    vals = ['"' + str(self.findingsTableModel.getValueAt(r, c)).replace('"','""') + '"'
                            for c in range(self.findingsTableModel.getColumnCount())]
                    f.write(','.join(vals) + '\n')
            self.stdout.println("[EXPORT] CSV saved: %s" % path)
        except Exception as e:
            self.stderr.println("[!] CSV export failed: %s" % e)

    # ─────────────────────────
    #  SCOPE MANAGEMENT
    # ─────────────────────────
    def load_scope(self):
        """Load custom scope entries from file."""
        try:
            import os
            if os.path.exists(self.scope_file):
                with open(self.scope_file, 'r') as f:
                    data = json.load(f)
                    self.scope_entries = data.get("entries", [])
                    self.log_to_console("[SCOPE] Loaded %d custom scope entries" % len(self.scope_entries))
        except Exception as e:
            pass  # Silently fail on first load

    def save_scope(self):
        """Save custom scope entries to file."""
        try:
            with self.scope_lock:
                data = {"entries": self.scope_entries, "version": self.CONFIG_VERSION}
            with open(self.scope_file, 'w') as f:
                json.dump(data, f, indent=2)
            self.stdout.println("[SCOPE] Saved %d entries" % len(self.scope_entries))
        except Exception as e:
            self.stderr.println("[!] Scope save error: %s" % e)

    def openScopeManager(self, event):
        """Open scope manager dialog to add/remove/manage targets."""
        try:
            from javax.swing import (JDialog, JTextField, JButton, JList, JScrollPane,
                                     DefaultListModel, JPanel, JLabel, BoxLayout, Box)
            from java.awt.event import ActionListener

            dialog = JDialog()
            dialog.setTitle("SILENTCHAIN - Scope Manager v%s" % self.VERSION)
            dialog.setModal(True)
            dialog.setSize(650, 500)
            dialog.setLocationRelativeTo(None)
            cp = dialog.getContentPane()
            cp.setBackground(Theme.BG_DARK)
            cp.setLayout(BoxLayout(cp, BoxLayout.Y_AXIS))

            # Header
            header = JLabel("Custom Target Scope Manager")
            header.setFont(Theme.FONT_TITLE)
            header.setForeground(Theme.ACCENT)
            header.setBorder(EmptyBorder(12, 12, 8, 12))
            cp.add(header)

            # Instructions
            instr = JLabel("Add domains/URLs to limit passive scanning. Burp's built-in scope is also checked.")
            instr.setFont(Theme.FONT_MONO_L)
            instr.setForeground(Theme.TEXT_MUTED)
            instr.setBorder(EmptyBorder(0, 12, 12, 12))
            cp.add(instr)

            # Input panel
            inputPanel = JPanel()
            inputPanel.setBackground(Theme.BG_MID)
            inputPanel.setLayout(BoxLayout(inputPanel, BoxLayout.X_AXIS))
            inputPanel.setBorder(EmptyBorder(8, 12, 8, 12))

            urlLabel = JLabel("URL:")
            urlLabel.setFont(Theme.FONT_MONO_B)
            urlLabel.setForeground(Theme.TEXT_PRIMARY)
            urlLabel.setPreferredSize(Dimension(60, 28))
            inputPanel.add(urlLabel)

            urlField = JTextField()
            urlField.setBackground(Theme.BG_DARKEST)
            urlField.setForeground(Theme.TEXT_PRIMARY)
            urlField.setCaretColor(Theme.TEXT_PRIMARY)
            urlField.setFont(Theme.FONT_MONO)
            urlField.setText("https://example.com")
            inputPanel.add(urlField)

            cp.add(inputPanel)

            # Scope list
            listLabel = JLabel("Scope Entries:")
            listLabel.setFont(Theme.FONT_MONO_B)
            listLabel.setForeground(Theme.TEXT_PRIMARY)
            listLabel.setBorder(EmptyBorder(8, 12, 4, 12))
            cp.add(listLabel)

            listModel = DefaultListModel()
            with self.scope_lock:
                for entry in self.scope_entries:
                    enabled_str = "[ON]" if entry.get("enabled", True) else "[OFF]"
                    listModel.addElement("%s %s" % (enabled_str, entry.get("url", "")))

            scopeList = JList(listModel)
            scopeList.setBackground(Theme.BG_MID)
            scopeList.setForeground(Theme.TEXT_PRIMARY)
            scopeList.setFont(Theme.FONT_MONO_L)
            scopeList.setSelectionBackground(Theme.BG_LIGHT)
            scopeList.setSelectionForeground(Theme.TEXT_PRIMARY)

            scrollPane = JScrollPane(scopeList)
            scrollPane.setBackground(Theme.BG_DARK)
            scrollPane.setBorder(EmptyBorder(4, 12, 8, 12))
            scrollPane.setPreferredSize(Dimension(600, 250))
            cp.add(scrollPane)

            # Button panel
            btnPanel = JPanel()
            btnPanel.setBackground(Theme.BG_DARK)
            btnPanel.setLayout(BoxLayout(btnPanel, BoxLayout.X_AXIS))
            btnPanel.setBorder(EmptyBorder(8, 12, 12, 12))

            extender_ref = self
            dialog_ref = [dialog]  # Mutable to close from handler

            def refresh_list():
                listModel.clear()
                with extender_ref.scope_lock:
                    for entry in extender_ref.scope_entries:
                        enabled_str = "[ON]" if entry.get("enabled", True) else "[OFF]"
                        listModel.addElement("%s %s" % (enabled_str, entry.get("url", "")))

            class AddHandler(ActionListener):
                def actionPerformed(self, e):
                    url = urlField.getText().strip()
                    if not url:
                        return
                    if not url.startswith('http'):
                        url = 'https://' + url
                    with extender_ref.scope_lock:
                        # Check for duplicates
                        for entry in extender_ref.scope_entries:
                            if entry.get("url") == url:
                                return  # Already exists
                        extender_ref.scope_entries.append({"url": url, "enabled": True})
                    extender_ref.save_scope()
                    refresh_list()
                    urlField.setText("")
                    extender_ref.log_to_console("[SCOPE] Added: %s" % url)

            class RemoveHandler(ActionListener):
                def actionPerformed(self, e):
                    idx = scopeList.getSelectedIndex()
                    if idx < 0:
                        return
                    with extender_ref.scope_lock:
                        if idx < len(extender_ref.scope_entries):
                            removed = extender_ref.scope_entries.pop(idx)
                            extender_ref.log_to_console("[SCOPE] Removed: %s" % removed.get("url"))
                    extender_ref.save_scope()
                    refresh_list()

            class ToggleHandler(ActionListener):
                def actionPerformed(self, e):
                    idx = scopeList.getSelectedIndex()
                    if idx < 0:
                        return
                    with extender_ref.scope_lock:
                        if idx < len(extender_ref.scope_entries):
                            entry = extender_ref.scope_entries[idx]
                            entry["enabled"] = not entry.get("enabled", True)
                            status = "Enabled" if entry["enabled"] else "Disabled"
                            extender_ref.log_to_console("[SCOPE] %s: %s" % (status, entry.get("url")))
                    extender_ref.save_scope()
                    refresh_list()

            class ClearHandler(ActionListener):
                def actionPerformed(self, e):
                    with extender_ref.scope_lock:
                        extender_ref.scope_entries = []
                    extender_ref.save_scope()
                    refresh_list()
                    extender_ref.log_to_console("[SCOPE] Cleared all entries")

            class CloseHandler(ActionListener):
                def actionPerformed(self, e):
                    dialog_ref[0].dispose()

            addBtn = styled_btn("Add", Theme.CONF_CERTAIN, action=AddHandler())
            removeBtn = styled_btn("Remove", Theme.SEV_HIGH, action=RemoveHandler())
            toggleBtn = styled_btn("Toggle", Theme.SEV_MED, action=ToggleHandler())
            clearBtn = styled_btn("Clear All", Color(0xFF, 0x17, 0x44), action=ClearHandler())
            closeBtn = styled_btn("Close", Theme.BG_LIGHT, fg=Theme.TEXT_PRIMARY, action=CloseHandler())

            for b in [addBtn, removeBtn, toggleBtn, clearBtn, Box.createHorizontalGlue(), closeBtn]:
                btnPanel.add(b)

            cp.add(btnPanel)
            dialog.setVisible(True)

        except Exception as e:
            self.stderr.println("[!] Scope manager error: %s" % e)

    # ─────────────────────────
    #  SETTINGS DIALOG
    # ─────────────────────────
    def openSettings(self, event):
        from javax.swing import (JDialog, JTabbedPane, JTextField, JComboBox,
                                 JPasswordField, JCheckBox)
        dialog = JDialog()
        dialog.setTitle("SILENTCHAIN Settings v%s" % self.VERSION)
        dialog.setModal(True)
        dialog.setSize(700, 580)
        dialog.setLocationRelativeTo(None)
        dialog.getContentPane().setBackground(Theme.BG_DARK)

        tabs = JTabbedPane()
        tabs.setBackground(Theme.BG_DARK)
        tabs.setForeground(Theme.TEXT_PRIMARY)

        # AI Provider tab
        aiPanel = JPanel(GridBagLayout())
        aiPanel.setBackground(Theme.BG_DARK)
        gbc = GridBagConstraints()
        gbc.insets = Insets(6, 8, 6, 8)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill   = GridBagConstraints.HORIZONTAL

        def add_row(panel, row, label_text, field):
            gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 1
            lbl = JLabel(label_text)
            lbl.setForeground(Theme.TEXT_MUTED)
            lbl.setFont(Theme.FONT_MONO)
            panel.add(lbl, gbc)
            gbc.gridx = 1; gbc.gridwidth = 2
            panel.add(field, gbc)
            gbc.gridwidth = 1

        providerCombo  = JComboBox(["Ollama","OpenAI","Claude","Gemini","Azure Foundry"])
        providerCombo.setSelectedItem(self.AI_PROVIDER)
        apiUrlField    = JTextField(self.API_URL, 30)
        apiKeyField    = JPasswordField(self.API_KEY, 30)
        maxTokensField = JTextField(str(self.MAX_TOKENS), 10)

        models_list = self.available_models if self.available_models else [self.MODEL]
        modelCombo = JComboBox(models_list)
        if self.MODEL in models_list: modelCombo.setSelectedItem(self.MODEL)

        for fld in [apiUrlField, apiKeyField, maxTokensField]:
            fld.setBackground(Theme.BG_MID)
            fld.setForeground(Theme.TEXT_PRIMARY)
            fld.setCaretColor(Theme.ACCENT)
            fld.setFont(Theme.FONT_MONO)

        from java.awt.event import ActionListener
        class ProviderListener(ActionListener):
            def __init__(self, f): self.f = f
            def actionPerformed(self, e):
                urls = {"Ollama":"http://localhost:11434","OpenAI":"https://api.openai.com/v1",
                        "Claude":"https://api.anthropic.com/v1",
                        "Gemini":"https://generativelanguage.googleapis.com/v1",
                        "Azure Foundry":"https://YOUR-RESOURCE.openai.azure.com"}
                p = str(e.getSource().getSelectedItem())
                if p in urls: self.f.setText(urls[p])
        providerCombo.addActionListener(ProviderListener(apiUrlField))

        add_row(aiPanel, 0, "AI Provider:", providerCombo)
        add_row(aiPanel, 1, "API URL:",     apiUrlField)
        add_row(aiPanel, 2, "API Key:",     apiKeyField)
        add_row(aiPanel, 3, "Model:",       modelCombo)
        add_row(aiPanel, 4, "Max Tokens:",  maxTokensField)

        gbc.gridx=0; gbc.gridy=5; gbc.gridwidth=3
        testBtn = styled_btn("Test Connection", Theme.ACCENT_DIM, Color.WHITE)
        ext_ref = self
        def do_test(e):
            testBtn.setEnabled(False); testBtn.setText("Testing...")
            old = (ext_ref.AI_PROVIDER, ext_ref.API_URL, ext_ref.API_KEY)
            ext_ref.AI_PROVIDER = str(providerCombo.getSelectedItem())
            ext_ref.API_URL = apiUrlField.getText()
            ext_ref.API_KEY = "".join(apiKeyField.getPassword())
            def run():
                try:
                    if not ext_ref.test_ai_connection():
                        ext_ref.AI_PROVIDER, ext_ref.API_URL, ext_ref.API_KEY = old
                finally:
                    SwingUtilities.invokeLater(lambda: (testBtn.setEnabled(True), testBtn.setText("Test Connection")))
            threading.Thread(target=run, daemon=True).start()
        testBtn.addActionListener(do_test)
        aiPanel.add(testBtn, gbc)
        tabs.addTab("AI Provider", aiPanel)

        # Advanced tab
        advPanel = JPanel(GridBagLayout())
        advPanel.setBackground(Theme.BG_DARK)
        gbc2 = GridBagConstraints()
        gbc2.insets = Insets(6,8,6,8); gbc2.anchor=GridBagConstraints.WEST
        gbc2.fill = GridBagConstraints.HORIZONTAL

        passiveChk = JCheckBox("Enable passive scanning", self.PASSIVE_SCANNING_ENABLED)
        verboseChk = JCheckBox("Verbose logging", self.VERBOSE)
        timeoutFld = JTextField(str(self.AI_REQUEST_TIMEOUT), 10)

        for w in [passiveChk, verboseChk]:
            w.setBackground(Theme.BG_DARK); w.setForeground(Theme.TEXT_PRIMARY)
            w.setFont(Theme.FONT_MONO)
        timeoutFld.setBackground(Theme.BG_MID); timeoutFld.setForeground(Theme.TEXT_PRIMARY)
        timeoutFld.setFont(Theme.FONT_MONO)

        rows_adv = [(0,"Passive Scan:", passiveChk),(1,"Verbose:", verboseChk),(2,"Timeout (s):", timeoutFld)]
        for r, lbl_txt, widget in rows_adv:
            gbc2.gridx=0; gbc2.gridy=r; gbc2.gridwidth=1
            l = JLabel(lbl_txt); l.setForeground(Theme.TEXT_MUTED); l.setFont(Theme.FONT_MONO)
            advPanel.add(l, gbc2)
            gbc2.gridx=1; gbc2.gridwidth=2; advPanel.add(widget, gbc2); gbc2.gridwidth=1

        tabs.addTab("Advanced", advPanel)

        # Save / Cancel
        btnRow = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 8))
        btnRow.setBackground(Theme.BG_MID)
        saveBtn   = styled_btn("Save",   Theme.CONF_CERTAIN)
        cancelBtn = styled_btn("Cancel", Theme.BG_LIGHT, fg=Theme.TEXT_MUTED)

        def do_save(e):
            self.AI_PROVIDER = str(providerCombo.getSelectedItem())
            self.API_URL     = apiUrlField.getText()
            self.API_KEY     = "".join(apiKeyField.getPassword())
            self.MODEL       = str(modelCombo.getSelectedItem())
            try: self.MAX_TOKENS = max(512, int(maxTokensField.getText()))
            except: self.MAX_TOKENS = 3072
            self.PASSIVE_SCANNING_ENABLED = passiveChk.isSelected()
            self.VERBOSE     = verboseChk.isSelected()
            try:
                t = int(timeoutFld.getText())
                self.AI_REQUEST_TIMEOUT = max(10, min(99999, t))
            except: self.AI_REQUEST_TIMEOUT = 60
            self._sync_scanning_button()
            self.save_config()
            self.refreshUI()
            dialog.dispose()

        saveBtn.addActionListener(do_save)
        cancelBtn.addActionListener(lambda e: dialog.dispose())
        btnRow.add(saveBtn); btnRow.add(cancelBtn)

        from javax.swing import JPanel as JP
        wrapper = JP(BorderLayout())
        wrapper.setBackground(Theme.BG_DARK)
        wrapper.add(tabs, BorderLayout.CENTER)
        wrapper.add(btnRow, BorderLayout.SOUTH)
        dialog.add(wrapper)
        dialog.setVisible(True)

    # ─────────────────────────
    #  CONFIG I/O
    # ─────────────────────────
    def load_config(self):
        try:
            import os
            if not os.path.exists(self.config_file): return
            with open(self.config_file, 'r') as f:
                cfg = json.load(f)
            self.AI_PROVIDER  = cfg.get("ai_provider", self.AI_PROVIDER)
            self.API_URL      = cfg.get("api_url", self.API_URL)
            self.API_KEY      = cfg.get("api_key", self.API_KEY)
            self.MODEL        = cfg.get("model", self.MODEL)
            self.MAX_TOKENS   = cfg.get("max_tokens", self.MAX_TOKENS)
            self.AI_REQUEST_TIMEOUT = cfg.get("ai_request_timeout", self.AI_REQUEST_TIMEOUT)
            self.VERBOSE      = cfg.get("verbose", self.VERBOSE)
            self.PASSIVE_SCANNING_ENABLED = cfg.get("passive_scanning_enabled", self.PASSIVE_SCANNING_ENABLED)
            self.AZURE_API_VERSION = cfg.get("azure_api_version", self.AZURE_API_VERSION)
        except Exception as e:
            pass  # stdout not ready yet

    def save_config(self):
        try:
            cfg = {
                "config_version": self.CONFIG_VERSION,
                "ai_provider": self.AI_PROVIDER, "api_url": self.API_URL,
                "api_key": self.API_KEY, "model": self.MODEL,
                "max_tokens": self.MAX_TOKENS, "ai_request_timeout": self.AI_REQUEST_TIMEOUT,
                "verbose": self.VERBOSE, "passive_scanning_enabled": self.PASSIVE_SCANNING_ENABLED,
                "azure_api_version": self.AZURE_API_VERSION,
                "version": self.VERSION, "last_saved": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            with open(self.config_file, 'w') as f:
                json.dump(cfg, f, indent=2)
            return True
        except Exception as e:
            self.stderr.println("[!] Save config failed: %s" % e)
            return False

    def apply_environment_config(self):
        try:
            import os
            az_ep  = os.environ.get("AZURE_OPENAI_ENDPOINT","").strip()
            az_key = os.environ.get("AZURE_OPENAI_API_KEY","").strip()
            az_dep = os.environ.get("AZURE_OPENAI_DEPLOYMENT","").strip()
            az_ver = os.environ.get("OPENAI_API_VERSION","").strip()
            if az_ver: self.AZURE_API_VERSION = az_ver
            if az_ep and az_key and (self.AI_PROVIDER == "Ollama" or not self.API_KEY):
                self.AI_PROVIDER = "Azure Foundry"
                self.API_URL = az_ep; self.API_KEY = az_key
                if az_dep: self.MODEL = az_dep
        except: pass

    def _load_dotenv_values(self):
        values = {}
        try:
            import os
            paths = [os.path.join(os.getcwd(), ".env"),
                     os.path.join(os.path.expanduser("~"), ".silentchain.env")]
            for p in paths:
                if p and os.path.isfile(p):
                    with open(p,'r') as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith('#') or '=' not in line: continue
                            k, v = line.split('=', 1)
                            k = k.strip().lstrip("export").strip()
                            v = v.strip().strip('"').strip("'")
                            if k: values[k] = v
                    break
        except: pass
        return values

    # ─────────────────────────
    #  CACHE I/O
    # ─────────────────────────
    def load_vuln_cache(self):
        try:
            import os
            if not os.path.exists(self.vuln_cache_file): return
            with open(self.vuln_cache_file, 'r') as f:
                payload = json.load(f)
            entries = payload.get("entries", {}) if isinstance(payload, dict) else {}
            with self.vuln_cache_lock:
                self.vuln_cache = entries if isinstance(entries, dict) else {}
            self.stdout.println("[CACHE] Loaded %d entries" % len(self.vuln_cache))
            self._ui_dirty = True
        except Exception as e:
            self.stderr.println("[!] Cache load failed: %s" % e)

    def save_vuln_cache(self):
        try:
            with self.vuln_cache_lock:
                snap = dict(self.vuln_cache)
            with open(self.vuln_cache_file, 'w') as f:
                json.dump({"version": self.VERSION,
                           "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                           "entries": snap}, f, indent=2)
            return True
        except Exception as e:
            self.stderr.println("[!] Cache save failed: %s" % e)
            return False

    def _async_save_cache(self):
        if not self._cache_dirty: return
        self._cache_dirty = False
        def run():
            try: self.save_vuln_cache()
            except: self._cache_dirty = True
        t = threading.Thread(target=run); t.setDaemon(True); t.start()

    # ─────────────────────────
    #  CACHE KEY / LOOKUP
    # ─────────────────────────
    def _get_request_signature(self, data):
        req_hdrs = [str(h).split(':',1)[0].strip().lower() for h in data.get("request_headers",[])[:10]]
        res_hdrs = [str(h).split(':',1)[0].strip().lower() for h in data.get("response_headers",[])[:10]]
        auth_present = any(h.lower().startswith(('authorization:','cookie:','x-api-key:'))
                          for h in data.get("request_headers",[]))
        auth_len = sum(len(h) for h in data.get("request_headers",[])
                      if h.lower().startswith(('authorization:','cookie:','x-api-key:')))
        sig = {"provider": self.AI_PROVIDER, "model": self.MODEL,
               "method": data.get("method",""), "url": str(data.get("url","")).split('?',1)[0],
               "status": data.get("status",0), "mime_type": data.get("mime_type",""),
               "param_names": sorted([p.get("name","") for p in data.get("params_sample",[]) if p.get("name")]),
               "req_headers": sorted(req_hdrs), "res_headers": sorted(res_hdrs),
               "auth_present": auth_present, "auth_len": auth_len}
        return hashlib.sha256(json.dumps(sig, sort_keys=True).encode('utf-8')).hexdigest()[:32]

    def _get_cached_findings(self, sig):
        with self.vuln_cache_lock:
            entry = self.vuln_cache.get(sig)
            if not entry: return None
            entry["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            entry["hit_count"] = int(entry.get("hit_count",0)) + 1
            findings = entry.get("findings", [])
        self._cache_dirty = True
        return findings if isinstance(findings, list) else []

    def _store_cached_findings(self, sig, url, findings):
        if isinstance(findings, dict): findings = [findings]
        normalized = [f for f in findings if isinstance(f, dict)]
        if not normalized: return
        with self.vuln_cache_lock:
            self.vuln_cache[sig] = {
                "url": str(url).split('?',1)[0],
                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "hit_count": 0, "findings": normalized
            }
        self._cache_dirty = True
        self._ui_dirty = True

    # ─────────────────────────
    #  HASHING
    # ─────────────────────────
    def _get_url_hash(self, url, params):
        param_names = sorted([p.getName() for p in params])
        raw = str(url).split('?')[0] + '|' + '|'.join(param_names)
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:32]

    def _get_finding_hash(self, url, title, cwe, param_name=""):
        raw = "%s|%s|%s|%s" % (str(url).split('?')[0], title.lower().strip(), cwe, param_name)
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:32]

    # ─────────────────────────
    #  TASK TRACKING
    # ─────────────────────────
    def addTask(self, task_type, url, status="Queued", messageInfo=None):
        with self.tasks_lock:
            task = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": task_type, "url": url, "status": status,
                    "start_time": time.time(), "messageInfo": messageInfo}
            self.tasks.append(task)
            with self.stats_lock: self.stats["total_requests"] += 1
            self._ui_dirty = True
            return len(self.tasks) - 1

    def updateTask(self, task_id, status, error=None):
        with self.tasks_lock:
            if task_id < len(self.tasks):
                self.tasks[task_id]["status"] = status
                self.tasks[task_id]["end_time"] = time.time()
                if error: self.tasks[task_id]["error"] = error
        self._ui_dirty = True

    def updateStats(self, key, n=1):
        with self.stats_lock:
            self.stats[key] = self.stats.get(key, 0) + n
        self._ui_dirty = True

    def log_to_console(self, msg):
        with self.console_lock:
            ts = datetime.now().strftime("%H:%M:%S")
            s = str(msg)
            if len(s) > 160: s = s[:157] + "..."
            self.console_messages.append("[%s] %s" % (ts, s))
            if len(self.console_messages) > self.max_console_messages:
                self.console_messages = self.console_messages[-self.max_console_messages:]
        self._ui_dirty = True

    def add_finding(self, finding_dict):
        """Store full rich finding dict (includes exploit/poc fields)."""
        with self.findings_lock_ui:
            self.findings_list.append(finding_dict)
        self._ui_dirty = True

    # ─────────────────────────
    #  BURP INTERFACE
    # ─────────────────────────
    def getTabCaption(self):    return "SILENTCHAIN"
    def getUiComponent(self):   return self.panel

    def createMenuItems(self, invocation):
        ctx = invocation.getInvocationContext()
        allowed = [invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
                   invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
                   invocation.CONTEXT_PROXY_HISTORY,
                   invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
                   invocation.CONTEXT_TARGET_SITE_MAP_TREE]
        if ctx not in allowed: return None
        msgs = invocation.getSelectedMessages()
        if not msgs or len(msgs) == 0: return None
        menu_list = ArrayList()
        item = JMenuItem("SILENTCHAIN: Analyze Request")
        item.setForeground(Theme.ACCENT)
        item.addActionListener(lambda x: self.analyzeFromContextMenu(msgs))
        menu_list.add(item)
        return menu_list

    def analyzeFromContextMenu(self, messages):
        t = threading.Thread(target=self._contextMenuThread, args=(messages,))
        t.setDaemon(True); t.start()

    def _contextMenuThread(self, messages):
        seen = set()
        for message in messages:
            try:
                req = self.helpers.analyzeRequest(message)
                url_str = str(req.getUrl())
                rb = message.getRequest()
                key = "%s|%s" % (url_str, hashlib.sha256(bytes(rb.tostring())).hexdigest()[:8] if rb else "")
                now = time.time()
                with self.context_menu_lock:
                    if now - self.context_menu_last_invoke.get(key, 0) < self.context_menu_debounce_time:
                        continue
                    self.context_menu_last_invoke[key] = now
                if key in seen: continue
                seen.add(key)

                if message.getResponse() is None:
                    resp = self.callbacks.makeHttpRequest(message.getHttpService(), rb)
                    if resp is None or resp.getResponse() is None: continue
                    message = resp

                task_id = self.addTask("CONTEXT", url_str, "Queued", message)
                self.thread_pool.submit(AnalyzeTask(self, message, url_str, task_id, forced=True))
            except Exception as e:
                self.stderr.println("[!] Context menu error: %s" % e)

    def doPassiveScan(self, baseRequestResponse):
        if not self.PASSIVE_SCANNING_ENABLED: return None
        try:
            req = self.helpers.analyzeRequest(baseRequestResponse)
            url_str = str(req.getUrl())
            if not self.is_in_scope(url_str): return None
            if self.should_skip_extension(url_str): return None
        except: url_str = "Unknown"
        task_id = self.addTask("PASSIVE", url_str, "Queued", baseRequestResponse)
        self.thread_pool.submit(AnalyzeTask(self, baseRequestResponse, url_str, task_id))
        return None

    def doActiveScan(self, brr, ip): return []
    def consolidateDuplicateIssues(self, a, b): return 0

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest or not self.PASSIVE_SCANNING_ENABLED: return
        if toolFlag != 4: return   # TOOL_PROXY = 4
        try:
            req = self.helpers.analyzeRequest(messageInfo)
            url_str = str(req.getUrl())
            if not self.is_in_scope(url_str): return
            if self.should_skip_extension(url_str): return
        except: url_str = "Unknown"
        task_id = self.addTask("HTTP", url_str, "Queued", messageInfo)
        self.thread_pool.submit(AnalyzeTask(self, messageInfo, url_str, task_id))

    def is_in_scope(self, url):
        """Check if URL is in Burp scope OR custom scope entries."""
        try:
            # Check Burp's built-in scope first
            from java.net import URL as JavaURL
            if self.callbacks.isInScope(JavaURL(url)):
                return True
        except:
            pass
        # Check custom scope entries
        try:
            url_base = url.split('?')[0].rstrip('/')
            with self.scope_lock:
                for entry in self.scope_entries:
                    if not entry.get("enabled", True):
                        continue
                    scope_url = entry.get("url", "").rstrip('/')
                    if url.startswith(scope_url) or url_base == scope_url:
                        return True
        except:
            pass
        return False

    def should_skip_extension(self, url):
        try:
            path = url.split('?')[0].lower()
            fname = path.split('/')[-1] if '/' in path else path
            if '.' in fname:
                ext = fname.split('.')[-1]
                if ext in self.SKIP_EXTENSIONS: return True
        except: pass
        return False

    # ─────────────────────────
    #  ANALYSIS ENGINE
    # ─────────────────────────
    def analyze(self, messageInfo, url_str=None, task_id=None):
        host = self._host_from_url(url_str or "unknown")
        host_sem = self.get_host_semaphore(host)
        host_sem.acquire()
        try:
            self.global_semaphore.acquire()
            try:
                self._rate_limit(task_id, "Waiting (Rate Limit)")
                if task_id is not None: self.updateTask(task_id, "Analyzing")
                self._perform_analysis(messageInfo, "HTTP", url_str, task_id)
                if task_id is not None: self.updateTask(task_id, "Completed")
            except Exception as e:
                self.stderr.println("[!] Analysis error: %s" % e)
                if task_id is not None: self.updateTask(task_id, "Error: %s" % str(e)[:30])
                self.updateStats("errors")
            finally:
                self.global_semaphore.release()
                self.refreshUI()
        finally:
            host_sem.release()

    def analyze_forced(self, messageInfo, url_str=None, task_id=None):
        host = self._host_from_url(url_str or "unknown")
        host_sem = self.get_host_semaphore(host)
        host_sem.acquire()
        try:
            self.global_semaphore.acquire()
            try:
                self._rate_limit(task_id, "Waiting (Rate Limit)")
                if task_id is not None: self.updateTask(task_id, "Analyzing (Forced)")
                self._perform_analysis(messageInfo, "CONTEXT", url_str, task_id, bypass_dedup=True)
                if task_id is not None: self.updateTask(task_id, "Completed")
            except Exception as e:
                self.stderr.println("[!] Forced analysis error: %s" % e)
                if task_id is not None: self.updateTask(task_id, "Error: %s" % str(e)[:30])
                self.updateStats("errors")
            finally:
                self.global_semaphore.release()
                self.refreshUI()
        finally:
            host_sem.release()

    def _rate_limit(self, task_id, status_msg):
        wait = self.min_delay - (time.time() - self.last_request_time)
        if wait > 0:
            if task_id is not None: self.updateTask(task_id, status_msg)
            time.sleep(wait)
        self.last_request_time = time.time()

    def get_host_semaphore(self, host):
        with self.host_semaphore_lock:
            if host not in self.host_semaphores:
                self.host_semaphores[host] = threading.Semaphore(2)
            return self.host_semaphores[host]

    def _host_from_url(self, url_str):
        try:
            import re
            m = re.match(r'https?://([^:/]+)', str(url_str))
            return m.group(1) if m else "unknown"
        except: return "unknown"

    def _perform_analysis(self, messageInfo, source, url_str=None, task_id=None, bypass_dedup=False):
        try:
            req = self.helpers.analyzeRequest(messageInfo)
            res = self.helpers.analyzeResponse(messageInfo.getResponse())
            url = str(req.getUrl())
            if not url_str: url_str = url

            params  = req.getParameters()
            url_hash = self._get_url_hash(url, params)

            if not bypass_dedup:
                with self.url_lock:
                    if url_hash in self.processed_urls:
                        if task_id is not None: self.updateTask(task_id, "Skipped (Duplicate)")
                        self.updateStats("skipped_duplicate")
                        return
                    self.processed_urls.add(url_hash)

            req_bytes  = messageInfo.getRequest()
            req_body   = ""
            try: req_body = self.helpers.bytesToString(req_bytes[req.getBodyOffset():])[:2000]
            except: req_body = "[binary]"

            req_hdrs = [str(h) for h in req.getHeaders()[:10]]

            res_bytes = messageInfo.getResponse()
            res_body  = ""
            try:
                raw = self.helpers.bytesToString(res_bytes[res.getBodyOffset():])
                res_body = self.smart_truncate(raw)
            except: res_body = "[binary]"

            res_hdrs = [str(h) for h in res.getHeaders()[:10]]
            params_sample = [{"name": p.getName(), "value": p.getValue()[:150],
                              "type": str(p.getType())} for p in params[:5]]
            idor_signals = self.extract_idor_signals(params_sample, url)

            data = {"url": url, "method": req.getMethod(), "status": res.getStatusCode(),
                    "mime_type": res.getStatedMimeType(), "params_count": len(params),
                    "params_sample": params_sample, "request_headers": req_hdrs,
                    "request_body": req_body, "response_headers": res_hdrs,
                    "response_body": res_body, "idor_signals": idor_signals}

            sig = self._get_request_signature(data)
            cached = None if bypass_dedup else self._get_cached_findings(sig)

            if cached is not None:
                findings = cached
                self.updateStats("cached_reused")
                self.updateStats("analyzed")
                self.log_to_console("[%s] CACHE HIT %s (%d findings)" % (source, url_str[:60], len(findings)))
            else:
                ai_text = self.ask_ai(self.build_prompt(data))
                if not ai_text:
                    if task_id is not None: self.updateTask(task_id, "Error (No AI response)")
                    self.updateStats("errors"); return

                self.updateStats("analyzed")
                findings = self._parse_ai_response(ai_text)
                if not findings:
                    if task_id is not None: self.updateTask(task_id, "Error (JSON parse)")
                    self.updateStats("errors"); return

                self._store_cached_findings(sig, url, findings)

            if not isinstance(findings, list): findings = [findings]

            created = 0
            for item in findings:
                if not isinstance(item, dict): continue
                title    = item.get("title", "AI Finding")
                severity = VALID_SEVERITIES.get(item.get("severity","information").lower().strip(), "Information")
                ai_conf  = item.get("confidence", 50)
                try: ai_conf = int(ai_conf)
                except: ai_conf = 50
                cwe      = item.get("cwe","")
                burp_conf = map_confidence(ai_conf)
                if not burp_conf:
                    self.updateStats("skipped_low_confidence"); continue

                param_name = params_sample[0].get("name","") if params_sample else ""
                fhash = self._get_finding_hash(url, title, cwe, param_name)
                with self.findings_lock:
                    if fhash in self.findings_cache:
                        self.updateStats("skipped_duplicate"); continue
                    self.findings_cache[fhash] = True

                # Build rich finding dict — this powers the detail panel
                rich_finding = {
                    "discovered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "url": url,
                    "title": title,
                    "severity": severity,
                    "confidence": burp_conf,
                    "detail": item.get("detail",""),
                    "cwe": cwe,
                    "owasp": item.get("owasp",""),
                    "remediation": item.get("remediation",""),
                    "evidence": item.get("evidence",""),
                    "param": item.get("param",""),
                    "affected_params": item.get("affected_params", []),
                    "exploit_path": item.get("exploit_path",""),
                    "exploit_steps": item.get("exploit_steps", []),
                    "poc_template": item.get("poc_template",""),
                    "poc_curl": item.get("poc_curl",""),
                    "poc_python": item.get("poc_python",""),
                    "business_impact": item.get("business_impact",""),
                    "cvss_score": item.get("cvss_score",""),
                    "references": item.get("references", []),
                }
                self.add_finding(rich_finding)

                # Also add to Burp scanner
                detail_html = self._build_burp_detail(rich_finding, params_sample)
                issue = CustomScanIssue(messageInfo.getHttpService(), req.getUrl(),
                                        [messageInfo], title, detail_html, severity, burp_conf)
                self.callbacks.addScanIssue(issue)
                self.updateStats("findings_created")
                created += 1

            self.log_to_console("[%s] %s → %d finding(s)" % (source, url_str[:60], created))
        except Exception as e:
            self.stderr.println("[!] _perform_analysis error: %s" % e)
            self.updateStats("errors")

    def _build_burp_detail(self, f, params_sample):
        """Build HTML detail string for Burp's Issues panel."""
        parts = ["<b>Description:</b><br>%s<br>" % f.get("detail","")]
        parts.append("<br><b>AI Confidence:</b> %d%%" % f.get("ai_conf", 50))
        if f.get("evidence"):
            parts.append("<br><b>Evidence:</b><br><code>%s</code>" % f["evidence"][:500])
        if f.get("exploit_path"):
            parts.append("<br><b>Exploitation:</b><br>%s" % f["exploit_path"])
        if f.get("exploit_steps"):
            steps = "".join("<li>%s</li>" % s for s in f["exploit_steps"])
            parts.append("<br><ol>%s</ol>" % steps)
        if f.get("poc_curl"):
            parts.append("<br><b>PoC (curl):</b><br><pre>%s</pre>" % f["poc_curl"][:800])
        if f.get("remediation"):
            parts.append("<br><b>Remediation:</b><br>%s" % f["remediation"])
        if f.get("cwe"):
            cid = f["cwe"].replace("CWE-","")
            parts.append("<br><b>CWE:</b> <a href='https://cwe.mitre.org/data/definitions/%s.html'>%s</a>" % (cid, f["cwe"]))
        if f.get("owasp"):
            parts.append("<br><b>OWASP:</b> %s" % f["owasp"])
        return "".join(parts)

    # ─────────────────────────
    #  PROMPT  (expanded for exploitation + PoC)
    # ─────────────────────────
    def build_prompt(self, data):
        return (
            "You are a senior penetration tester. Output ONLY a JSON array. NO markdown, NO text outside JSON.\n\n"
            "Analyze the HTTP request/response below for ALL of:\n"
            "1. OWASP Top 10 (2021) — SQLi, XSS, Broken Auth, etc.\n"
            "2. IDOR / BOLA — numeric/UUID IDs in params, sequential IDs in paths\n"
            "3. Mass Assignment — unexpected POST params not validated server-side\n"
            "4. SSRF — URL/redirect/webhook params pointing to internal resources\n"
            "5. JWT weaknesses — alg:none, HS256 weak secret, missing validation\n"
            "6. GraphQL — introspection, batch abuse, __schema in body\n"
            "7. OAuth/OIDC misconfigs — open redirect_uri, missing state, token leak\n"
            "8. HTTP Request Smuggling — TE+CL conflicts, chunked encoding abuse\n"
            "9. Cache Poisoning — X-Forwarded-Host, X-Original-URL, fat GET\n"
            "10. Business Logic — price/qty tampering, role param, discount abuse\n"
            "11. Information Disclosure — stack traces, secrets, internal IPs\n"
            "12. Prototype Pollution — __proto__, constructor.prototype in JSON\n"
            "13. Missing Security Headers — CSP, HSTS, X-Frame-Options absent\n"
            "14. API Versioning — v1 vs v2 access control gaps\n\n"
            "For each finding with confidence >= 50, output a JSON object with ALL fields:\n"
            "{\n"
            "  \"title\": \"short vuln name\",\n"
            "  \"severity\": \"High|Medium|Low|Information\",\n"
            "  \"confidence\": 50-100,\n"
            "  \"detail\": \"technical description of the vulnerability\",\n"
            "  \"cwe\": \"CWE-XXX\",\n"
            "  \"owasp\": \"AXX:2021 Name\",\n"
            "  \"cvss_score\": \"7.5\",\n"
            "  \"param\": \"vulnerable_parameter_name\",\n"
            "  \"affected_params\": [\"param1\", \"param2\"],\n"
            "  \"evidence\": \"exact snippet from request/response proving the issue\",\n"
            "  \"exploit_path\": \"one-paragraph description of how an attacker exploits this\",\n"
            "  \"exploit_steps\": [\n"
            "    \"Step 1: Intercept the request to /api/users/123\",\n"
            "    \"Step 2: Change the numeric ID to another user's ID\",\n"
            "    \"Step 3: Observe the server returns another user's data\"\n"
            "  ],\n"
            "  \"poc_curl\": \"curl -X GET 'https://target.com/api/users/124' -H 'Authorization: Bearer <token>'\",\n"
            "  \"poc_python\": \"import requests\\nrequests.get('https://target.com/api/users/124', headers={'Authorization': 'Bearer TOKEN'})\",\n"
            "  \"poc_template\": \"burp-style request with [INJECT] marker\",\n"
            "  \"business_impact\": \"what an attacker can achieve if exploited\",\n"
            "  \"remediation\": \"specific fix with code example if possible\",\n"
            "  \"references\": [\"https://owasp.org/...\", \"https://portswigger.net/...\"]\n"
            "}\n\n"
            "Rules:\n"
            "- Output [] if no issues found with confidence >= 50\n"
            "- Do NOT fabricate evidence — only report what is visible in the data\n"
            "- exploit_steps must be concrete and actionable, not generic\n"
            "- poc_curl must be a real runnable command using values from the request\n\n"
            "HTTP Data:\n%s\n"
        ) % json.dumps(data, indent=2)

    # ─────────────────────────
    #  AI RESPONSE PARSING
    # ─────────────────────────
    def _parse_ai_response(self, ai_text):
        ai_text = ai_text.strip()
        import re
        if ai_text.startswith("```"):
            ai_text = re.sub(r'^```(?:json)?\n?|```$', '', ai_text, flags=re.MULTILINE).strip()
        # Strip <think>...</think> tags (DeepSeek)
        ai_text = re.sub(r'<think>.*?</think>', '', ai_text, flags=re.DOTALL).strip()

        start = ai_text.find('[')
        end   = ai_text.rfind(']')
        if start != -1 and end != -1:
            try:
                r = json.loads(ai_text[start:end+1])
                return r if isinstance(r, list) else [r]
            except: pass

        obj_s = ai_text.find('{')
        obj_e = ai_text.rfind('}')
        if obj_s != -1 and obj_e != -1:
            try:
                r = json.loads('[' + ai_text[obj_s:obj_e+1] + ']')
                return r if isinstance(r, list) else [r]
            except: pass

        return self._repair_json(ai_text)

    def _repair_json(self, text):
        try:
            import re
            text = re.sub(r',(\s*[}\]])', r'\1', text)
            text = text.strip()
            if not text.startswith('['):
                s = text.find('{')
                if s != -1: text = '[' + text[s:]
            if not text.endswith(']'):
                e = text.rfind('}')
                if e != -1: text = text[:e+1] + ']'
            return json.loads(text)
        except:
            return []

    # ─────────────────────────
    #  AI PROVIDERS
    # ─────────────────────────
    def ask_ai(self, prompt):
        try:
            return {
                "Ollama":       self._ask_ollama,
                "OpenAI":       self._ask_openai,
                "Claude":       self._ask_claude,
                "Gemini":       self._ask_gemini,
                "Azure Foundry":self._ask_azure_foundry,
            }[self.AI_PROVIDER](prompt)
        except KeyError:
            self.stderr.println("[!] Unknown provider: %s" % self.AI_PROVIDER)
        except Exception as e:
            self.stderr.println("[!] AI error: %s" % e)
        return None

    def _ask_ollama(self, prompt):
        url = self.API_URL.rstrip('/') + "/api/generate"
        payload = {"model": self.MODEL, "prompt": prompt, "stream": False,
                   "format": "json", "options": {"temperature": 0.0, "num_predict": self.MAX_TOKENS}}
        for attempt in range(3):
            try:
                req = urllib2.Request(url, data=json.dumps(payload).encode("utf-8"),
                                      headers={"Content-Type": "application/json"})
                resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
                data = json.loads(resp.read().decode("utf-8","ignore"))
                text = data.get("response","").strip()
                if data.get("done_reason") == "length":
                    text = self._fix_truncated(text)
                return text
            except urllib2.URLError as e:
                if attempt < 2 and ("timed out" in str(e) or "timeout" in str(e).lower()):
                    self.stderr.println("[!] Timeout, retry %d/2" % (attempt+1)); time.sleep(2)
                else: raise
        return None

    def _ask_openai(self, prompt):
        req = urllib2.Request(
            self.API_URL.rstrip('/') + "/chat/completions",
            data=json.dumps({"model": self.MODEL, "max_tokens": self.MAX_TOKENS, "temperature": 0.0,
                             "messages": [{"role":"user","content": prompt}]}).encode("utf-8"),
            headers={"Content-Type":"application/json","Authorization":"Bearer "+self.API_KEY})
        data = json.loads(urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT).read())
        return data["choices"][0]["message"]["content"]

    def _ask_claude(self, prompt):
        req = urllib2.Request(
            self.API_URL.rstrip('/') + "/messages",
            data=json.dumps({"model": self.MODEL, "max_tokens": self.MAX_TOKENS,
                             "messages": [{"role":"user","content": prompt}]}).encode("utf-8"),
            headers={"Content-Type":"application/json","x-api-key": self.API_KEY,
                     "anthropic-version":"2023-06-01"})
        data = json.loads(urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT).read())
        return data["content"][0]["text"]

    def _ask_gemini(self, prompt):
        req = urllib2.Request(
            self.API_URL.rstrip('/') + "/models/%s:generateContent?key=%s" % (self.MODEL, self.API_KEY),
            data=json.dumps({"contents":[{"parts":[{"text":prompt}]}],
                             "generationConfig":{"maxOutputTokens":self.MAX_TOKENS,"temperature":0.0}
                            }).encode("utf-8"),
            headers={"Content-Type":"application/json"})
        data = json.loads(urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT).read())
        return data["candidates"][0]["content"]["parts"][0]["text"]

    def _ask_azure_foundry(self, prompt):
        if not self.API_KEY or not self.API_URL: raise Exception("Azure config incomplete")
        base = self.API_URL.split('?',1)[0].rstrip('/')
        chat_url = self._build_azure_url(base)
        if "api-version=" not in chat_url:
            sep = '&' if '?' in chat_url else '?'
            chat_url += sep + "api-version=" + (self.AZURE_API_VERSION or "2024-06-01")
        req = urllib2.Request(chat_url,
            data=json.dumps({"messages":[{"role":"user","content":prompt}],
                             "max_tokens":self.MAX_TOKENS,"temperature":0.0}).encode("utf-8"),
            headers={"Content-Type":"application/json","api-key":self.API_KEY})
        data = json.loads(urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT).read())
        return data["choices"][0]["message"]["content"]

    def _build_azure_url(self, base):
        if "/chat/completions" in base: return base
        if "/openai/deployments/" in base: return base + "/chat/completions"
        if not self.MODEL: raise Exception("Azure deployment name required in Model field")
        return "%s/openai/deployments/%s/chat/completions" % (base, urllib.quote(self.MODEL, safe=''))

    def _fix_truncated(self, text):
        if not text: return "[]"
        try: json.loads(text); return text
        except: pass
        e = text.rfind('}')
        if e > 0:
            p = text[:e+1]
            if p.count('[') > p.count(']'):
                try: json.loads(p+']'); return p+']'
                except: pass
        return "[]"

    # ─────────────────────────
    #  CONNECTION TESTS
    # ─────────────────────────
    def test_ai_connection(self):
        self.stdout.println("[CONN] Testing %s @ %s" % (self.AI_PROVIDER, self.API_URL))
        try:
            return {
                "Ollama": self._test_ollama, "OpenAI": self._test_openai,
                "Claude": self._test_claude, "Gemini": self._test_gemini,
                "Azure Foundry": self._test_azure,
            }[self.AI_PROVIDER]()
        except KeyError:
            self.stderr.println("[!] Unknown provider"); return False
        except Exception as e:
            self.stderr.println("[!] Connection failed: %s" % e); return False

    def _test_ollama(self):
        url = self.API_URL.rstrip('/api/generate').rstrip('/') + "/api/tags"
        resp = urllib2.urlopen(urllib2.Request(url), timeout=10)
        data = json.loads(resp.read())
        if 'models' in data:
            self.available_models = [m['name'] for m in data['models']]
            self.stdout.println("[CONN] Ollama OK — %d models" % len(self.available_models))
            if self.MODEL not in self.available_models and self.available_models:
                self.MODEL = self.available_models[0]
            return True
        return False

    def _test_openai(self):
        if not self.API_KEY: self.stderr.println("[!] OpenAI key required"); return False
        req = urllib2.Request("https://api.openai.com/v1/models",
                              headers={"Authorization":"Bearer "+self.API_KEY})
        data = json.loads(urllib2.urlopen(req, timeout=10).read())
        if 'data' in data:
            self.available_models = [m['id'] for m in data['data'] if 'gpt' in m.get('id','')]
            self.stdout.println("[CONN] OpenAI OK"); return True
        return False

    def _test_claude(self):
        if not self.API_KEY: self.stderr.println("[!] Claude key required"); return False
        try:
            req = urllib2.Request(self.API_URL.rstrip('/') + "/messages",
                data=json.dumps({"model": self.MODEL or "claude-3-5-sonnet-20241022",
                                 "max_tokens":5,"messages":[{"role":"user","content":"ping"}]}).encode(),
                headers={"Content-Type":"application/json","x-api-key":self.API_KEY,"anthropic-version":"2023-06-01"})
            resp = urllib2.urlopen(req, timeout=10)
            if resp.getcode() == 200:
                self.available_models = ["claude-opus-4-6","claude-sonnet-4-6","claude-haiku-4-5-20251001"]
                self.stdout.println("[CONN] Claude OK"); return True
        except urllib2.HTTPError as e:
            if e.code == 429:
                self.stdout.println("[CONN] Claude OK (rate-limited)"); return True
            raise
        return False

    def _test_gemini(self):
        if not self.API_KEY: self.stderr.println("[!] Gemini key required"); return False
        self.available_models = ["gemini-1.5-pro","gemini-1.5-flash","gemini-pro"]
        self.stdout.println("[CONN] Gemini configured"); return True

    def _test_azure(self):
        if not self.API_KEY or not self.API_URL: self.stderr.println("[!] Azure config incomplete"); return False
        self.available_models = [self.MODEL] if self.MODEL else []
        self.stdout.println("[CONN] Azure Foundry configured"); return True

    # ─────────────────────────
    #  UTILITY
    # ─────────────────────────
    def smart_truncate(self, body, max_len=5000):
        if len(body) <= max_len: return body
        head, tail = 3500, 1000
        trunc = len(body) - head - tail
        return body[:head] + "\n...[%d chars truncated]...\n" % trunc + body[-tail:]

    def extract_idor_signals(self, params_sample, url):
        signals = []
        try:
            import re
            IDOR_NAMES = {'id','user_id','account_id','order_id','invoice_id','file_id',
                          'doc_id','record_id','item_id','uid','pid','customer_id','profile_id','ref'}
            path_ids = re.findall(r'/(\d{1,10})(?:/|$|\?)', str(url))
            if path_ids: signals.append({"type":"path_numeric_id","values":path_ids[:3]})
            if re.search(r'[0-9a-f-]{36}', str(url), re.I): signals.append({"type":"path_uuid"})
            for p in params_sample:
                v = p.get("value",""); n = p.get("name","")
                if re.match(r'^\d+$', v) and len(v) <= 10:
                    signals.append({"type":"numeric_param","name":n,"value":v})
                elif re.match(r'^[0-9a-f-]{36}$', v, re.I):
                    signals.append({"type":"uuid_param","name":n})
                elif n.lower() in IDOR_NAMES:
                    signals.append({"type":"idor_name_match","name":n,"value":v[:20]})
        except: pass
        return signals

    def print_logo(self):
        self.stdout.println("=" * 60)
        self.stdout.println("  SILENTCHAIN AI v%s — Community Edition" % self.VERSION)
        self.stdout.println("  Dark terminal UI | Exploitation paths | PoC templates")
        self.stdout.println("  Provider: %s | Model: %s" % (self.AI_PROVIDER, self.MODEL))
        self.stdout.println("=" * 60)
