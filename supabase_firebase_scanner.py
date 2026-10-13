"""Passive and active Supabase/Firebase exposure checks for Burp's Jython API."""

import base64
import json
import re
import threading
from datetime import datetime

from burp import (
    IBurpExtender,
    ITab,
    IHttpListener,
    IHttpRequestResponse,
    IScanIssue,
)
from java.awt import BorderLayout, FlowLayout
from java.awt.event import ActionListener
from java.net import URL
from javax.swing import (
    JButton,
    JCheckBox,
    JLabel,
    JOptionPane,
    JPanel,
    JScrollPane,
    JSplitPane,
    SwingUtilities,
    SwingWorker,
    JTable,
    JTextArea,
)
from javax.swing.table import DefaultTableModel
from jarray import array


_SUPABASE_URL = re.compile(r"https?://[a-z0-9-]+\.supabase\.co", re.I)
_SUPABASE_PUBLISHABLE = re.compile(r"\bsb_publishable_[A-Za-z0-9_-]{20,}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_SUPABASE_TABLE = re.compile(
    r"(?:\.from\s*\(\s*|/rest/v1/)[\"']?([A-Za-z_][A-Za-z0-9_]{0,62})",
    re.I,
)
_FIREBASE_API_KEY = re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")
_FIREBASE_PROJECT = re.compile(
    r"(?:projectId|project_id)\s*[\"']?\s*[:=]\s*[\"']([A-Za-z0-9][A-Za-z0-9._-]{0,127})",
    re.I,
)
_FIREBASE_DB = re.compile(
    r"https?://[A-Za-z0-9-]+(?:\.firebaseio\.com|-default-rtdb\.[A-Za-z0-9-]+\.firebasedatabase\.app)",
    re.I,
)
_MAX_TARGETS = 500
_MAX_TABLES = 20


class _Action(ActionListener):
    def __init__(self, callback):
        self.callback = callback

    def actionPerformed(self, event):
        self.callback()


class _Runnable(object):
    def __init__(self, callback):
        self.callback = callback

    def run(self):
        self.callback()


class _ReadOnlyModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False


def _supabase_anon_keys(text):
    keys = set(_SUPABASE_PUBLISHABLE.findall(text))
    for token in _JWT.findall(text):
        try:
            payload = token.split(".")[1]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
            if claims.get("role") == "anon":
                keys.add(token)
        except Exception:
            pass
    return keys


class _AuditIssue(IScanIssue):
    def __init__(self, helpers, message_info, name, detail, reported_url):
        self.helpers = helpers
        self.message_info = message_info
        self.name = name
        self.detail = detail
        service = message_info.getHttpService()
        self.service = service
        self.url = URL(reported_url)

    def getUrl(self):
        return self.url

    def getIssueName(self):
        return self.name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "Medium"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "The backend accepted an unauthenticated request for data or a write operation."

    def getRemediationBackground(self):
        return "Restrict access with row-level security or Firebase Security Rules. Avoid placing privileged service credentials in client code."

    def getIssueDetail(self):
        return self.detail

    def getRemediationDetail(self):
        return "Review the affected table or Firebase path, enable restrictive access rules, and retest with an unauthenticated client."

    def getHttpMessages(self):
        return array([self.message_info], IHttpRequestResponse)

    def getHttpService(self):
        return self.service


class BurpExtender(IBurpExtender, ITab, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.lock = threading.RLock()
        self.targets = {}
        self.displayed_targets = []
        self.reported_issues = set()
        self.running = False
        callbacks.setExtensionName("Supabase and Firebase Misconfiguration Scanner")
        self._build_ui()
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        callbacks.printOutput("Supabase and Firebase Misconfiguration Scanner loaded")

    def getTabCaption(self):
        return "BaaS Scanner"

    def getUiComponent(self):
        return self.panel

    def processHttpMessage(self, tool_flag, message_is_request, message_info):
        try:
            request = message_info.getRequest()
            if request is None:
                return
            request_info = self.helpers.analyzeRequest(message_info.getHttpService(), request)
            url = str(request_info.getUrl())
            request_text = self.helpers.bytesToString(request)
            pieces = [url, request_text]
            response = message_info.getResponse()
            if response is not None:
                response_info = self.helpers.analyzeResponse(response)
                pieces.append(
                    self.helpers.bytesToString(response[response_info.getBodyOffset():])
                )
            self._observe("\n".join(pieces))
        except Exception as error:
            self.callbacks.printError("BaaS passive scan failed: " + str(error))

    def _build_ui(self):
        self.panel = JPanel(BorderLayout(6, 6))
        self.model = _ReadOnlyModel(
            ["Service", "Target", "Credential", "Tables", "Last check", "Evidence"], 0
        )
        self.table = JTable(self.model)
        self.table.setAutoCreateRowSorter(True)

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        self.check_button = JButton("Check selected")
        self.check_button.addActionListener(_Action(self._check_selected))
        self.write_box = JCheckBox("Probe Supabase writes (may persist a row)", False)
        self.clear_button = JButton("Clear targets")
        self.clear_button.addActionListener(_Action(self._clear_targets))
        controls.add(self.check_button)
        controls.add(self.write_box)
        controls.add(self.clear_button)
        self.status_label = JLabel(
            "Passive discovery is on. Active requests are restricted to Burp scope."
        )
        self.panel.add(controls, BorderLayout.NORTH)

        self.details = JTextArea(4, 80)
        self.details.setEditable(False)
        self.details.setLineWrap(True)
        split = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            JScrollPane(self.table),
            JScrollPane(self.details),
        )
        split.setResizeWeight(0.75)
        self.panel.add(split, BorderLayout.CENTER)
        self.panel.add(self.status_label, BorderLayout.SOUTH)

    def _observe(self, text):
        normalized = str(text)
        supabase_urls = sorted(set(match.rstrip("/.") for match in _SUPABASE_URL.findall(normalized)))
        anon_keys = sorted(_supabase_anon_keys(normalized))
        tables = sorted(set(_SUPABASE_TABLE.findall(normalized)))
        firebase_keys = sorted(set(_FIREBASE_API_KEY.findall(normalized)))
        project_ids = sorted(set(_FIREBASE_PROJECT.findall(normalized)))
        database_urls = sorted(set(match.rstrip("/.") for match in _FIREBASE_DB.findall(normalized)))

        with self.lock:
            for index, endpoint in enumerate(supabase_urls):
                target = self._new_target("supabase:" + endpoint, "Supabase")
                if target is None:
                    continue
                target["url"] = endpoint
                target["anon_key"] = anon_keys[min(index, len(anon_keys) - 1)] if anon_keys else target.get("anon_key", "")
                target["tables"].update(tables)
            count = max(len(project_ids), len(database_urls), 1 if firebase_keys else 0)
            for index in range(count):
                project = project_ids[min(index, len(project_ids) - 1)] if project_ids else ""
                database_url = database_urls[min(index, len(database_urls) - 1)] if database_urls else ""
                if not project and database_url:
                    project = database_url.split("//", 1)[1].split(".", 1)[0]
                    project = project.replace("-default-rtdb", "")
                if not project:
                    continue
                target = self._new_target("firebase:" + project, "Firebase")
                if target is None:
                    continue
                target["project_id"] = project
                target["database_url"] = database_url or target.get("database_url", "")
                target["api_key"] = firebase_keys[min(index, len(firebase_keys) - 1)] if firebase_keys else target.get("api_key", "")

        if supabase_urls or project_ids or database_urls:
            SwingUtilities.invokeLater(_Runnable(self._refresh_table))

    def _new_target(self, key, provider):
        target = self.targets.get(key)
        if target is None and len(self.targets) < _MAX_TARGETS:
            target = {
                "key": key,
                "provider": provider,
                "url": "",
                "anon_key": "",
                "project_id": "",
                "database_url": "",
                "api_key": "",
                "tables": set(),
                "last_check": "Not checked",
                "evidence": "Configuration observed in traffic",
            }
            self.targets[key] = target
        return target

    def _refresh_table(self):
        with self.lock:
            targets = list(self.targets.values())
            self.displayed_targets = targets
        self.model.setRowCount(0)
        for target in targets:
            credential = target["anon_key"] or target["api_key"]
            if credential:
                credential = credential[:12] + "..." + credential[-5:]
            self.model.addRow(
                [
                    target["provider"],
                    target["url"] or target["project_id"],
                    credential or "Not observed",
                    ", ".join(sorted(target["tables"])),
                    target["last_check"],
                    target["evidence"],
                ]
            )

    def _selected_target(self):
        row = self.table.getSelectedRow()
        if row < 0:
            return None
        model_row = self.table.convertRowIndexToModel(row)
        with self.lock:
            return (
                self.displayed_targets[model_row]
                if model_row < len(self.displayed_targets)
                else None
            )

    def _check_selected(self):
        if self.running:
            return
        target = self._selected_target()
        if target is None:
            self.status_label.setText("Select an observed target first.")
            return
        if target["provider"] == "Supabase" and not target["tables"]:
            self.status_label.setText("No table names found. Observe the app's API calls, then retry.")
            return
        if target["provider"] == "Supabase" and not target["anon_key"]:
            self.status_label.setText("No anon/publishable key found for this Supabase project.")
            return
        if target["provider"] == "Firebase" and not (target["database_url"] or target["project_id"]):
            self.status_label.setText("Firebase database URL or project ID was not observed.")
            return
        test_writes = (
            target["provider"] == "Supabase" and self.write_box.isSelected()
        )
        if test_writes:
            answer = JOptionPane.showConfirmDialog(
                self.panel,
                "The Supabase POST probe can create a persistent row. It sends an empty JSON object and cannot guarantee cleanup. Continue?",
                "Confirm potentially persistent write",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE,
            )
            if answer != JOptionPane.YES_OPTION:
                return

        with self.lock:
            target = dict(target)
            target["tables"] = set(target["tables"])
        self.running = True
        self.check_button.setEnabled(False)
        self.status_label.setText("Checking %s access..." % target["provider"])
        extension = self

        class CheckWorker(SwingWorker):
            def doInBackground(worker_self):
                return extension._run_checks(target, test_writes)

            def done(worker_self):
                extension.running = False
                extension.check_button.setEnabled(True)
                try:
                    result = worker_self.get()
                    with extension.lock:
                        live_target = extension.targets.get(target["key"])
                        if live_target is not None:
                            live_target["last_check"] = datetime.now().strftime("%H:%M:%S")
                            live_target["evidence"] = result["summary"][:180]
                    extension.details.setText(result["details"])
                    extension.status_label.setText(result["summary"])
                    extension._refresh_table()
                except Exception as error:
                    extension.status_label.setText("Active check failed: " + str(error))

        CheckWorker().execute()

    def _run_checks(self, target, test_writes):
        observations = []
        issues = []
        if target["provider"] == "Supabase":
            for table in sorted(target["tables"])[:_MAX_TABLES]:
                path = "/rest/v1/%s?select=*&limit=1" % table
                response = self._send(target["url"], "GET", path, target["anon_key"], "")
                if response is None:
                    observations.append("%s: no response" % table)
                    continue
                status, body, exchange = response
                readable = False
                if status == 200:
                    try:
                        parsed = json.loads(body)
                        readable = isinstance(parsed, list)
                    except Exception:
                        pass
                if readable:
                    detail = "Anonymous SELECT succeeded for Supabase table '%s' (HTTP %d)." % (table, status)
                    observations.append(detail)
                    issues.append((
                        "Supabase table anonymously readable", detail, target,
                        target["url"] + path, exchange,
                    ))
                else:
                    observations.append("%s: read check HTTP %d; access not confirmed" % (table, status))
                if test_writes:
                    write_response = self._send(
                        target["url"], "POST", "/rest/v1/%s" % table,
                        target["anon_key"], "{}",
                    )
                    if write_response is None:
                        observations.append("%s: write probe received no response" % table)
                    elif 200 <= write_response[0] < 300:
                        detail = "Anonymous POST was accepted for Supabase table '%s' (HTTP %d); a row may have been created." % (table, write_response[0])
                        observations.append(detail)
                        issues.append((
                            "Supabase table accepts anonymous writes", detail, target,
                            target["url"] + "/rest/v1/%s" % table,
                            write_response[2],
                        ))
                    else:
                        observations.append("%s: write check HTTP %d; write access not confirmed" % (table, write_response[0]))
        else:
            if target["database_url"]:
                response = self._send(target["database_url"], "GET", "/.json?shallow=true", "", "")
                if response is None:
                    observations.append("Firebase Realtime Database: no response")
                else:
                    status, body, exchange = response
                    try:
                        parsed = json.loads(body)
                    except Exception:
                        parsed = None
                    exposed = status == 200 and parsed not in (None, {}, [])
                    if exposed:
                        detail = "Unauthenticated Firebase Realtime Database read returned data (HTTP %d)." % status
                        observations.append(detail)
                        issues.append((
                            "Firebase Realtime Database is publicly readable", detail, target,
                            target["database_url"].rstrip("/") + "/.json?shallow=true",
                            exchange,
                        ))
                    else:
                        observations.append("Firebase Realtime Database: HTTP %d; public data read not confirmed" % status)
            if target["project_id"] and target["api_key"]:
                remote_path = "/v1/projects/%s/remoteConfig?key=%s" % (
                    target["project_id"], target["api_key"],
                )
                response = self._send(
                    "https://firebaseremoteconfig.googleapis.com", "GET", remote_path, "", ""
                )
                if response is None:
                    observations.append("Firebase Remote Config: no response")
                elif response[0] == 200:
                    detail = "Unauthenticated Firebase Remote Config request returned a template (HTTP 200)."
                    observations.append(detail)
                    issues.append((
                        "Firebase Remote Config is publicly readable", detail, target,
                        "https://firebaseremoteconfig.googleapis.com" + remote_path,
                        response[2],
                    ))
                else:
                    observations.append("Firebase Remote Config: HTTP %d; public access not confirmed" % response[0])
            elif target["project_id"]:
                observations.append("Firebase Remote Config: API key not observed")

        for name, detail, issue_target, reported_url, exchange in issues:
            self._report_issue(issue_target, name, detail, reported_url, exchange)
        summary = "%s active check(s); %d confirmed exposure(s)." % (
            len(observations), len(issues),
        )
        if not observations:
            observations.append("No testable endpoint was found in the observed configuration.")
        return {"summary": summary, "details": "\n".join(observations)}

    def _send(self, base_url, method, path, api_key, body):
        full_url = base_url.rstrip("/")
        url = URL(full_url)
        host = str(url.getHost())
        port = int(url.getPort())
        if port < 0:
            port = 443 if url.getProtocol().lower() == "https" else 80
        request_path = path if path.startswith("/") else "/" + path
        if not self.callbacks.isInScope(URL(full_url + request_path)):
            return None
        default_port = 443 if url.getProtocol().lower() == "https" else 80
        headers = [
            "%s %s HTTP/1.1" % (method, request_path),
            "Host: %s%s" % (host, (":" + str(port)) if port != default_port else ""),
            "Accept: application/json",
            "Accept-Encoding: identity",
            "Connection: close",
        ]
        if api_key:
            headers.append("apikey: " + api_key)
            headers.append("Authorization: Bearer " + api_key)
        if method == "POST":
            headers.extend(["Content-Type: application/json", "Prefer: return=minimal"])
        if body:
            headers.append("Content-Length: " + str(len(body)))
        raw = "\r\n".join(headers) + "\r\n\r\n" + body
        service = self.helpers.buildHttpService(host, port, str(url.getProtocol()))
        exchange = self.callbacks.makeHttpRequest(service, self.helpers.stringToBytes(raw))
        response = exchange.getResponse() if exchange is not None else None
        if response is None:
            return None
        response_info = self.helpers.analyzeResponse(response)
        response_body = self.helpers.bytesToString(response[response_info.getBodyOffset():])
        return int(response_info.getStatusCode()), response_body, exchange

    def _report_issue(self, target, name, detail, reported_url, exchange):
        signature = (target["key"], name)
        with self.lock:
            if signature in self.reported_issues:
                return
            self.reported_issues.add(signature)
        try:
            self.callbacks.addScanIssue(
                _AuditIssue(self.helpers, exchange, name, detail, reported_url)
            )
        except Exception as error:
            self.callbacks.printError("Could not create audit issue: " + str(error))

    def _clear_targets(self):
        if self.running:
            return
        with self.lock:
            self.targets = {}
            self.displayed_targets = []
            self.reported_issues = set()
        self.model.setRowCount(0)
        self.details.setText("")
        self.status_label.setText("Observed targets cleared.")