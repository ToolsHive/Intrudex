import re
from app.db import db
from sqlalchemy import func
from itertools import chain
from datetime import datetime
from rich.pretty import Pretty
from rich.syntax import Syntax
import xml.etree.ElementTree as ET
from rich import print as rich_print
from flask import Blueprint, request, jsonify, render_template_string
from app.models.logs import SysmonLog, ApplicationLog, SecurityLog, SystemLog, ClientHost

logs_bp = Blueprint('logs', __name__, url_prefix='/api/logs')

def sanitize_xml_data(raw_data):
    """Remove invalid XML characters from raw data."""
    return re.sub(r'[^\x09\x0A\x0D\x20-\x7F]', '', raw_data)

def pretty_xml_rich(xml_str):
    try:
        return Syntax(xml_str, "xml", theme="monokai", line_numbers=True)
    except Exception:
        return xml_str

def parse_xml_event_data(xml_data, field_map, namespace):
    """Extract fields from XML using a field mapping."""
    root = ET.fromstring(xml_data)
    data = {}
    for key, (xpath, is_attr, default, cast) in field_map.items():
        if is_attr:
            elem = root.find(xpath, namespaces=namespace)
            value = elem.attrib.get(is_attr) if elem is not None and is_attr in elem.attrib else default
        else:
            value = root.findtext(xpath, namespaces=namespace) or default
        if cast and value not in (None, '', 'Unknown'):
            try:
                value = cast(value)
            except Exception:
                value = default
        data[key] = value
    return data

def get_or_create_client_host(hostname):
    if not hostname:
        return None
    client = ClientHost.query.filter_by(hostname=hostname).first()
    if not client:
        client = ClientHost(hostname=hostname)
        db.session.add(client)
        db.session.commit()
    return client

@logs_bp.route('/sysmon', methods=['POST'], strict_slashes=False)
def sysmon_logs():
    try:
        raw_data = request.data.decode('utf-8', errors='replace')
        rich_print("[bold cyan][API] Raw XML Data (Before Sanitization):[/bold cyan]")
        rich_print(pretty_xml_rich(raw_data))
        sanitized_data = sanitize_xml_data(raw_data)
        rich_print("[bold green][API] Raw XML Data (After Sanitization):[/bold green]")
        rich_print(pretty_xml_rich(sanitized_data))
        namespace = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        field_map = {
            "event_id": (".//ns:EventID", False, 0, int),
            "time_created": (".//ns:TimeCreated", "SystemTime", None, lambda v: datetime.fromisoformat(v.replace('Z', '+00:00'))),
            "computer": (".//ns:Computer", False, "Unknown", None),
            "process_guid": (".//ns:Data[@Name='ProcessGuid']", False, "Unknown", None),
            "process_id": (".//ns:Data[@Name='ProcessId']", False, 0, int),
            "image": (".//ns:Data[@Name='Image']", False, "Unknown", None),
            "image_loaded": (".//ns:Data[@Name='ImageLoaded']", False, "Unknown", None),
            "file_version": (".//ns:Data[@Name='FileVersion']", False, "Unknown", None),
            "description": (".//ns:Data[@Name='Description']", False, "Unknown", None),
            "product": (".//ns:Data[@Name='Product']", False, "Unknown", None),
            "company": (".//ns:Data[@Name='Company']", False, "Unknown", None),
            "original_file_name": (".//ns:Data[@Name='OriginalFileName']", False, "Unknown", None),
            "hashes": (".//ns:Data[@Name='Hashes']", False, "Unknown", None),
            "signed": (".//ns:Data[@Name='Signed']", False, False, lambda v: v == 'true'),
            "signature": (".//ns:Data[@Name='Signature']", False, "Unknown", None),
            "signature_status": (".//ns:Data[@Name='SignatureStatus']", False, "Unknown", None),
            "user": (".//ns:Data[@Name='User']", False, "Unknown", None),
            "rule_name": (".//ns:Data[@Name='RuleName']", False, "Unknown", None),
        }
        event_data = parse_xml_event_data(sanitized_data, field_map, namespace)
        rich_print("[bold magenta][API] Extracted Event Data:[/bold magenta]")
        rich_print(Pretty(event_data, expand_all=True))
        # --- Always get hostname from header first ---
        hostname = request.headers.get('X-Hostname') or event_data.get('computer') or request.args.get('hostname')
        client = get_or_create_client_host(hostname)
        event_data.pop('hostname', None)
        log = SysmonLog(**event_data, client_id=client.id if client else None)
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Log saved successfully"}), 201
    except ET.ParseError as e:
        rich_print(f"[bold red][API] XML Parse Error:[/bold red] {e}")
        return jsonify({"error": f"Failed to parse XML: {str(e)}"}), 400
    except Exception as e:
        rich_print(f"[bold red][API] General Error:[/bold red] {e}")
        return jsonify({"error": str(e)}), 500

@logs_bp.route('/application', methods=['POST'], strict_slashes=False)
def application_logs():
    try:
        raw_data = request.data.decode('utf-8', errors='replace')
        rich_print("[bold cyan][API] Raw XML Data (Before Sanitization):[/bold cyan]")
        rich_print(pretty_xml_rich(raw_data))
        sanitized_data = sanitize_xml_data(raw_data)
        rich_print("[bold green][API] Raw XML Data (After Sanitization):[/bold green]")
        rich_print(pretty_xml_rich(sanitized_data))
        namespace = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        field_map = {
            "event_id": (".//ns:EventID", False, 0, int),
            "time_created": (".//ns:TimeCreated", "SystemTime", None, lambda v: datetime.fromisoformat(v.replace('Z', '+00:00'))),
            "computer": (".//ns:Computer", False, "Unknown", None),
            "process_guid": (".//ns:Data[@Name='ProcessGuid']", False, "Unknown", None),
            "process_id": (".//ns:Data[@Name='ProcessId']", False, 0, int),
            "image": (".//ns:Data[@Name='Image']", False, "Unknown", None),
            "target_object": (".//ns:Data[@Name='TargetObject']", False, "Unknown", None),
            "details": (".//ns:Data[@Name='Details']", False, "", None),
            "event_type": (".//ns:Data[@Name='EventType']", False, "Unknown", None),
            "user": (".//ns:Data[@Name='User']", False, "Unknown", None),
            "rule_name": (".//ns:Data[@Name='RuleName']", False, "", None),
        }
        event_data = parse_xml_event_data(sanitized_data, field_map, namespace)
        rich_print("[bold magenta][API] Extracted Application Event Data:[/bold magenta]")
        rich_print(Pretty(event_data, expand_all=True))
        hostname = request.headers.get('X-Hostname') or event_data.get('computer') or request.args.get('hostname')
        client = get_or_create_client_host(hostname)
        event_data.pop('hostname', None)
        log = ApplicationLog(**event_data, client_id=client.id if client else None)
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Application log saved successfully"}), 201
    except ET.ParseError as e:
        rich_print(f"[bold red][API] XML Parse Error:[/bold red] {e}")
        return jsonify({"error": f"Failed to parse XML: {str(e)}"}), 400
    except Exception as e:
        rich_print(f"[bold red][API] General Error:[/bold red] {e}")
        return jsonify({"error": str(e)}), 500

@logs_bp.route('/security', methods=['POST'], strict_slashes=False)
def security_logs():
    try:
        raw_data = request.data.decode('utf-8', errors='replace')
        rich_print("[bold cyan][API] Raw XML Data (Before Sanitization):[/bold cyan]")
        rich_print(pretty_xml_rich(raw_data))
        sanitized_data = sanitize_xml_data(raw_data)
        rich_print("[bold green][API] Raw XML Data (After Sanitization):[/bold green]")
        rich_print(pretty_xml_rich(sanitized_data))
        namespace = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        field_map = {
            "event_id": (".//ns:EventID", False, 0, int),
            "time_created": (".//ns:TimeCreated", "SystemTime", None, lambda v: datetime.fromisoformat(v.replace('Z', '+00:00'))),
            "computer": (".//ns:Computer", False, "Unknown", None),
            "target_user_name": (".//ns:Data[@Name='TargetUserName']", False, None, None),
            "target_domain_name": (".//ns:Data[@Name='TargetDomainName']", False, None, None),
            "target_sid": (".//ns:Data[@Name='TargetSid']", False, None, None),
            "subject_user_sid": (".//ns:Data[@Name='SubjectUserSid']", False, None, None),
            "subject_user_name": (".//ns:Data[@Name='SubjectUserName']", False, None, None),
            "subject_domain_name": (".//ns:Data[@Name='SubjectDomainName']", False, None, None),
            "subject_logon_id": (".//ns:Data[@Name='SubjectLogonId']", False, None, None),
            "caller_process_id": (".//ns:Data[@Name='CallerProcessId']", False, None, None),
            "caller_process_name": (".//ns:Data[@Name='CallerProcessName']", False, None, None),
        }
        event_data = parse_xml_event_data(sanitized_data, field_map, namespace)
        rich_print("[bold magenta][API] Extracted Security Event Data:[/bold magenta]")
        rich_print(Pretty(event_data, expand_all=True))
        hostname = request.headers.get('X-Hostname') or event_data.get('computer') or request.args.get('hostname')
        client = get_or_create_client_host(hostname)
        event_data.pop('hostname', None)
        log = SecurityLog(**event_data, client_id=client.id if client else None)
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Security log saved successfully"}), 201
    except ET.ParseError as e:
        rich_print(f"[bold red][API] XML Parse Error:[/bold red] {e}")
        return jsonify({"error": f"Failed to parse XML: {str(e)}"}), 400
    except Exception as e:
        rich_print(f"[bold red][API] General Error:[/bold red] {e}")
        return jsonify({"error": str(e)}), 500

@logs_bp.route('/system', methods=['POST'], strict_slashes=False)
def system_logs():
    try:
        raw_data = request.data.decode('utf-8', errors='replace')
        rich_print("[bold cyan][API] Raw XML Data (Before Sanitization):[/bold cyan]")
        rich_print(pretty_xml_rich(raw_data))
        sanitized_data = sanitize_xml_data(raw_data)
        rich_print("[bold green][API] Raw XML Data (After Sanitization):[/bold green]")
        rich_print(pretty_xml_rich(sanitized_data))
        namespace = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        root = ET.fromstring(sanitized_data)

        def get_attr(elem, attr):
            return elem.attrib.get(attr) if elem is not None and attr in elem.attrib else None

        event_id = int(root.findtext('.//ns:EventID', namespaces=namespace) or 0)
        time_created_str = get_attr(root.find('.//ns:TimeCreated', namespaces=namespace), 'SystemTime')
        time_created = datetime.fromisoformat(time_created_str.replace('Z', '+00:00')) if time_created_str else None
        computer = root.findtext('.//ns:Computer', namespaces=namespace) or "Unknown"
        provider = root.find('.//ns:Provider', namespaces=namespace)
        provider_name = get_attr(provider, 'Name')
        provider_guid = get_attr(provider, 'Guid')
        event_source_name = get_attr(provider, 'EventSourceName')
        event_record_id = int(root.findtext('.//ns:EventRecordID', namespaces=namespace) or 0)
        execution = root.find('.//ns:Execution', namespaces=namespace)
        process_id = int(get_attr(execution, 'ProcessID') or 0)
        thread_id = int(get_attr(execution, 'ThreadID') or 0)
        user_id = get_attr(root.find('.//ns:Security', namespaces=namespace), 'UserID')

        event_data_elem = root.find('.//ns:EventData', namespaces=namespace)
        event_data = {}
        if event_data_elem is not None:
            for data_elem in event_data_elem.findall('ns:Data', namespaces=namespace):
                name = get_attr(data_elem, 'Name')
                value = data_elem.text
                if name:
                    event_data[name] = value

        rich_print("[bold magenta][API] Extracted System Event Data:[/bold magenta]")
        rich_print(Pretty({
            "event_id": event_id,
            "time_created": time_created,
            "computer": computer,
            "provider_name": provider_name,
            "provider_guid": provider_guid,
            "event_source_name": event_source_name,
            "event_record_id": event_record_id,
            "process_id": process_id,
            "thread_id": thread_id,
            "user_id": user_id,
            "event_data": event_data
        }, expand_all=True))

        hostname = request.headers.get('X-Hostname') or computer or request.args.get('hostname')
        client = get_or_create_client_host(hostname)
        log = SystemLog(
            event_id=event_id,
            time_created=time_created,
            computer=computer,
            provider_name=provider_name,
            provider_guid=provider_guid,
            event_source_name=event_source_name,
            event_record_id=event_record_id,
            process_id=process_id,
            thread_id=thread_id,
            user_id=user_id,
            event_data=event_data,
            client_id=client.id if client else None
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "System log saved successfully"}), 201
    except ET.ParseError as e:
        rich_print(f"[bold red][API] XML Parse Error:[/bold red] {e}")
        return jsonify({"error": f"Failed to parse XML: {str(e)}"}), 400
    except Exception as e:
        rich_print(f"[bold red][API] General Error:[/bold red] {e}")
        return jsonify({"error": str(e)}), 500

@logs_bp.route('/counts', methods=['GET'])
def get_log_counts():
    return jsonify({
        "sysmon": SysmonLog.query.count(),
        "application": ApplicationLog.query.count(),
        "security": SecurityLog.query.count(),
        "system": SystemLog.query.count()
    })

@logs_bp.route('/recent', methods=['GET'])
def get_recent_logs():
    total_limit = int(request.args.get('limit', 10))
    table_count = 4
    per_table = total_limit // table_count
    remainder = total_limit % table_count

    # Distribute the remainder to the first few tables
    per_table_limits = [per_table + (1 if i < remainder else 0) for i in range(table_count)]

    # Helper functions
    def get_user_field(log):
        if isinstance(log, SystemLog):
            return getattr(log, "computer", "")
        elif isinstance(log, SysmonLog):
            return getattr(log, "user", "")
        elif isinstance(log, ApplicationLog):
            return getattr(log, "user", "")
        elif isinstance(log, SecurityLog):
            return getattr(log, "subject_user_name", "") or getattr(log, "user", "")
        return ""

    def get_event_id(log):
        return getattr(log, "event_id", "")

    def get_details_field(log):
        if isinstance(log, SystemLog):
            return getattr(log, "provider_name", "") or getattr(log, "event_data", "")
        elif isinstance(log, SysmonLog):
            return getattr(log, "image", "") or getattr(log, "company", "")
        elif isinstance(log, ApplicationLog):
            return getattr(log, "target_object", "") or getattr(log, "details", "")
        elif isinstance(log, SecurityLog):
            return getattr(log, "subject_user_name", "") or getattr(log, "target_user_name", "")
        return ""

    def is_valid(log):
        user = get_user_field(log)
        event_id = get_event_id(log)
        details = get_details_field(log)
        def is_unknown(val):
            return not val or str(val).strip().lower() == "unknown"
        return not (is_unknown(user) or is_unknown(event_id) or is_unknown(details))

    # Fetch more than needed, filter, and then trim
    sysmon_logs = [log for log in SysmonLog.query.order_by(SysmonLog.time_created.desc()).limit(per_table_limits[0]*10).all() if is_valid(log)]
    app_logs = [log for log in ApplicationLog.query.order_by(ApplicationLog.time_created.desc()).limit(per_table_limits[1]*10).all() if is_valid(log)]
    security_logs = [log for log in SecurityLog.query.order_by(SecurityLog.time_created.desc()).limit(per_table_limits[2]*10).all() if is_valid(log)]
    system_logs = [log for log in SystemLog.query.order_by(SystemLog.time_created.desc()).limit(per_table_limits[3]*10).all() if is_valid(log)]

    # Take up to per_table_limits from each, but not more than available
    sysmon_logs = sysmon_logs[:per_table_limits[0]]
    app_logs = app_logs[:per_table_limits[1]]
    security_logs = security_logs[:per_table_limits[2]]
    system_logs = system_logs[:per_table_limits[3]]

    # If we have less than total_limit, fill from remaining logs from all tables (prioritize missing types)
    all_logs = sysmon_logs + app_logs + security_logs + system_logs
    used_ids = set((type(log).__name__, log.id) for log in all_logs)
    if len(all_logs) < total_limit:
        # Gather remaining valid logs from all tables, excluding already used logs, and try to balance types
        extra_logs = []
        log_sources = [
            [l for l in SysmonLog.query.order_by(SysmonLog.time_created.desc()).all() if is_valid(l)],
            [l for l in ApplicationLog.query.order_by(ApplicationLog.time_created.desc()).all() if is_valid(l)],
            [l for l in SecurityLog.query.order_by(SecurityLog.time_created.desc()).all() if is_valid(l)],
            [l for l in SystemLog.query.order_by(SystemLog.time_created.desc()).all() if is_valid(l)],
        ]
        # Interleave logs from each type to fill up to total_limit
        pointers = [0, 0, 0, 0]
        while len(all_logs) + len(extra_logs) < total_limit:
            added = False
            for idx, logs in enumerate(log_sources):
                while pointers[idx] < len(logs):
                    log = logs[pointers[idx]]
                    pointers[idx] += 1
                    unique_id = (type(log).__name__, log.id)
                    if unique_id not in used_ids:
                        extra_logs.append(log)
                        used_ids.add(unique_id)
                        added = True
                        break
            if not added:
                break  # No more logs to add
        all_logs += extra_logs

    # Sort by time_created descending and trim to total_limit
    all_logs = sorted(all_logs, key=lambda log: log.time_created or datetime.min, reverse=True)[:total_limit]

    def log_detail(log):
        if isinstance(log, SystemLog):
            return f"Provider: {log.provider_name or ''}, EventRecordID: {getattr(log, 'event_record_id', '')}"
        elif isinstance(log, SysmonLog):
            return f"Image: {getattr(log, 'image', '')}, Company: {getattr(log, 'company', '')}"
        elif isinstance(log, ApplicationLog):
            return f"Target: {getattr(log, 'target_object', '')}, Details: {getattr(log, 'details', '')}"
        elif isinstance(log, SecurityLog):
            return f"Subject: {getattr(log, 'subject_user_name', '')}, Target: {getattr(log, 'target_user_name', '')}"
        return ""

    rows = []
    for log in all_logs:
        if isinstance(log, SystemLog):
            log_type = "System"
            badge = "badge-system"
            view_func = f"showSystemLogDetail({log.id})"
            event_id = getattr(log, "event_id", "")
            user = getattr(log, "computer", "")
        elif isinstance(log, SysmonLog):
            log_type = "Sysmon"
            badge = "badge-sysmon"
            view_func = f"showSysmonLogDetail({log.id})"
            event_id = getattr(log, "event_id", "")
            user = getattr(log, "user", "")
        elif isinstance(log, ApplicationLog):
            log_type = "Application"
            badge = "badge-application"
            view_func = f"showApplicationLogDetail({log.id})"
            event_id = getattr(log, "event_id", "")
            user = getattr(log, "user", "")
        elif isinstance(log, SecurityLog):
            log_type = "Security"
            badge = "badge-security"
            view_func = f"showSecurityLogDetail({log.id})"
            event_id = getattr(log, "event_id", "")
            user = getattr(log, "subject_user_name", "") or getattr(log, "user", "")
        else:
            log_type = "Unknown"
            badge = ""
            view_func = "#"
            event_id = ""
            user = ""

        detail = log_detail(log)
        rows.append(f"""
        <tr class="border-b border-gray-800 hover:bg-gray-800 transition cursor-pointer" data-log-id="{log.id}" data-log-type="{log_type}">
            <td class="py-2 px-3">
                <span class="badge {badge}">{log_type}</span>
            </td>
            <td class="py-2 px-3 text-gray-400">{log.time_created.strftime('%Y-%m-%d %H:%M:%S') if log.time_created else ''}</td>
            <td class="py-2 px-3 text-blue-300">#{event_id}</td>
            <td class="py-2 px-3 text-green-300">{user}</td>
            <td class="py-2 px-3 text-gray-200">{detail}</td>
            <td class="py-2 px-3">
                <button class="px-3 py-1 rounded bg-blue-700 text-white text-xs font-semibold hover:bg-blue-600 transition" onclick="event.stopPropagation(); {view_func};">View</button>
            </td>
        </tr>
        """)
    return render_template_string('<tbody id="log-table-body">\n' + '\n'.join(rows) + '\n</tbody>')

@logs_bp.route('/system/<int:log_id>', methods=['GET'])
def get_system_log_detail(log_id):
    log = SystemLog.query.get_or_404(log_id)
    # Render event_data as a table if it's a dict
    event_data_html = ""
    if isinstance(log.event_data, dict) and log.event_data:
        event_data_html = "<table class='min-w-full text-sm text-left mb-2'><thead><tr><th class='py-1 px-2 text-blue-300'>Key</th><th class='py-1 px-2 text-gray-300'>Value</th></tr></thead><tbody>"
        for k, v in log.event_data.items():
            event_data_html += f"<tr><td class='py-1 px-2 text-blue-200'>{k}</td><td class='py-1 px-2 text-gray-200'>{v}</td></tr>"
        event_data_html += "</tbody></table>"
    else:
        event_data_html = f"<pre>{log.event_data}</pre>"

    html = f"""
    <div class="modal-title">System Log Details</div>
    <div class="modal-row"><span class="modal-label">Event ID:</span> {log.event_id}</div>
    <div class="modal-row"><span class="modal-label">Time:</span> {log.time_created}</div>
    <div class="modal-row"><span class="modal-label">Computer:</span> {log.computer}</div>
    <div class="modal-row"><span class="modal-label">Provider:</span> {log.provider_name or ''}</div>
    <div class="modal-row"><span class="modal-label">Process ID:</span> {log.process_id or ''}</div>
    <div class="modal-row"><span class="modal-label">Thread ID:</span> {log.thread_id or ''}</div>
    <div class="modal-row"><span class="modal-label">User ID:</span> {log.user_id or ''}</div>
    <div class="modal-row"><span class="modal-label">Event Data:</span></div>
    {event_data_html}
    """
    return html

@logs_bp.route('/sysmon/<int:log_id>', methods=['GET'])
def get_sysmon_log_detail(log_id):
    log = SysmonLog.query.get_or_404(log_id)
    html = f"""
    <div class="modal-title">Sysmon Log Details</div>
    <div class="modal-row"><span class="modal-label">Event ID:</span> {log.event_id}</div>
    <div class="modal-row"><span class="modal-label">Time:</span> {log.time_created}</div>
    <div class="modal-row"><span class="modal-label">User:</span> {log.user or ''}</div>
    <div class="modal-row"><span class="modal-label">Image:</span> {log.image or ''}</div>
    <div class="modal-row"><span class="modal-label">Company:</span> {log.company or ''}</div>
    <div class="modal-row"><span class="modal-label">Hashes:</span> {log.hashes or ''}</div>
    <div class="modal-row"><span class="modal-label">Signed:</span> {log.signed}</div>
    """
    return html

@logs_bp.route('/application/<int:log_id>', methods=['GET'])
def get_application_log_detail(log_id):
    log = ApplicationLog.query.get_or_404(log_id)
    html = f"""
    <div class="modal-title">Application Log Details</div>
    <div class="modal-row"><span class="modal-label">Event ID:</span> {log.event_id}</div>
    <div class="modal-row"><span class="modal-label">Time:</span> {log.time_created}</div>
    <div class="modal-row"><span class="modal-label">User:</span> {log.user or ''}</div>
    <div class="modal-row"><span class="modal-label">Target Object:</span> {log.target_object or ''}</div>
    <div class="modal-row"><span class="modal-label">Details:</span> {log.details or ''}</div>
    <div class="modal-row"><span class="modal-label">Event Type:</span> {log.event_type or ''}</div>
    """
    return html

@logs_bp.route('/security/<int:log_id>', methods=['GET'])
def get_security_log_detail(log_id):
    log = SecurityLog.query.get_or_404(log_id)
    html = f"""
    <div class="modal-title">Security Log Details</div>
    <div class="modal-row"><span class="modal-label">Event ID:</span> {log.event_id}</div>
    <div class="modal-row"><span class="modal-label">Time:</span> {log.time_created}</div>
    <div class="modal-row"><span class="modal-label">Computer:</span> {log.computer or ''}</div>
    <div class="modal-row"><span class="modal-label">Subject User:</span> {log.subject_user_name or ''}</div>
    <div class="modal-row"><span class="modal-label">Target User:</span> {log.target_user_name or ''}</div>
    <div class="modal-row"><span class="modal-label">Domain:</span> {log.subject_domain_name or ''}</div>
    <div class="modal-row"><span class="modal-label">Caller Process:</span> {log.caller_process_name or ''}</div>
    """
    return html

@logs_bp.route('/top-users', methods=['GET'])
def get_top_users():
    # Aggregate users from all log tables
    sysmon_users = db.session.query(SysmonLog.user, func.count().label('count')).group_by(SysmonLog.user)
    app_users = db.session.query(ApplicationLog.user, func.count().label('count')).group_by(ApplicationLog.user)
    sec_users = db.session.query(SecurityLog.subject_user_name, func.count().label('count')).group_by(SecurityLog.subject_user_name)
    sys_users = db.session.query(SystemLog.computer, func.count().label('count')).group_by(SystemLog.computer)

    user_stats = {}

    # Helper to add counts
    def add_count(user, log_type, count):
        if not user or str(user).strip().lower() == "unknown":
            return
        if user not in user_stats:
            user_stats[user] = {"total": 0, "Sysmon": 0, "Application": 0, "Security": 0, "System": 0}
        user_stats[user][log_type] += count
        user_stats[user]["total"] += count

    for user, count in sysmon_users:
        add_count(user, "Sysmon", count)
    for user, count in app_users:
        add_count(user, "Application", count)
    for user, count in sec_users:
        add_count(user, "Security", count)
    for user, count in sys_users:
        add_count(user, "System", count)

    # Sort by total count
    sorted_users = sorted(user_stats.items(), key=lambda x: x[1]["total"], reverse=True)

    # Only include users that actually have logs in at least one table
    filtered_users = []
    for user, stats in sorted_users:
        # Check if user has at least one log in any table
        has_logs = False
        if SysmonLog.query.filter(SysmonLog.user == user).first():
            has_logs = True
        elif ApplicationLog.query.filter(ApplicationLog.user == user).first():
            has_logs = True
        elif SecurityLog.query.filter(SecurityLog.subject_user_name == user).first():
            has_logs = True
        elif SystemLog.query.filter(SystemLog.computer == user).first():
            has_logs = True
        if has_logs:
            filtered_users.append((user, stats))
        if len(filtered_users) >= 10:
            break

    items = []
    for user, stats in filtered_users:
        initials = ''.join([w[0] for w in user.split() if w]).upper()[:2] or user[:2].upper()
        breakdown = []
        for log_type in ["Sysmon", "Application", "Security", "System"]:
            if stats[log_type]:
                color = {
                    "Sysmon": "bg-blue-700",
                    "Application": "bg-green-700",
                    "Security": "bg-purple-700",
                    "System": "bg-red-700"
                }[log_type]
                breakdown.append(
                    f"<span class='px-2 py-0.5 rounded {color} text-white text-xs mr-1'>{log_type}: {stats[log_type]}</span>"
                )
        items.append(f"""
        <li class="flex items-center gap-3 bg-gray-800 rounded-lg px-4 py-2 shadow hover-raise cursor-pointer" data-user="{user}">
            <span class="inline-flex items-center justify-center w-8 h-8 rounded-full bg-blue-700 text-white font-bold text-lg">{initials}</span>
            <div class="flex-1 min-w-0">
                <div class="font-semibold truncate" title="{user}">{user}</div>
                <div class="flex flex-wrap mt-1">{''.join(breakdown)}</div>
            </div>
            <span class="badge badge-system">{stats['total']} logs</span>
        </li>
        """)
    return render_template_string('<ul id="top-users" class="space-y-3">\n' + '\n'.join(items) + '\n</ul>')

@logs_bp.route('/user/<user>', methods=['GET'])
def get_user_detail(user):
    # Fetch recent logs for this user from all log types, ensuring uniqueness by event_id, time_created, and log_type
    sysmon = SysmonLog.query.filter(SysmonLog.user == user).order_by(SysmonLog.time_created.desc()).limit(20).all()
    app = ApplicationLog.query.filter(ApplicationLog.user == user).order_by(ApplicationLog.time_created.desc()).limit(20).all()
    sec = SecurityLog.query.filter(SecurityLog.subject_user_name == user).order_by(SecurityLog.time_created.desc()).limit(20).all()
    sys = SystemLog.query.filter(SystemLog.computer == user).order_by(SystemLog.time_created.desc()).limit(20).all()

    # Use a set of (log_type, event_id, time_created, extra_key) to ensure uniqueness
    seen = set()
    logs_by_type = {'Sysmon': [], 'Application': [], 'Security': [], 'System': []}

    def unique_key(log, log_type):
        # Use event_id, time_created, and a distinguishing field for each log type
        if log_type == "Sysmon":
            extra = getattr(log, "image", None)
        elif log_type == "Application":
            extra = getattr(log, "target_object", None)
        elif log_type == "Security":
            extra = getattr(log, "target_user_name", None)
        elif log_type == "System":
            extra = getattr(log, "provider_name", None)
        else:
            extra = None
        return (log_type, getattr(log, "event_id", None), getattr(log, "time_created", None), extra)

    for log in sysmon:
        k = unique_key(log, "Sysmon")
        if k not in seen:
            logs_by_type["Sysmon"].append(log)
            seen.add(k)
    for log in app:
        k = unique_key(log, "Application")
        if k not in seen:
            logs_by_type["Application"].append(log)
            seen.add(k)
    for log in sec:
        k = unique_key(log, "Security")
        if k not in seen:
            logs_by_type["Security"].append(log)
            seen.add(k)
    for log in sys:
        k = unique_key(log, "System")
        if k not in seen:
            logs_by_type["System"].append(log)
            seen.add(k)

    html = f"<div class='modal-title'>User: {user}</div>"

    def log_row(log, log_type):
        if log_type == "Sysmon":
            return f"<div class='modal-row'><span class='modal-label'>[Sysmon]</span> Event: {log.event_id} | Time: {log.time_created} | Image: {log.image or ''} | Company: {log.company or ''}</div>"
        elif log_type == "Application":
            return f"<div class='modal-row'><span class='modal-label'>[Application]</span> Event: {log.event_id} | Time: {log.time_created} | Target: {log.target_object or ''} | Details: {log.details or ''}</div>"
        elif log_type == "Security":
            return f"<div class='modal-row'><span class='modal-label'>[Security]</span> Event: {log.event_id} | Time: {log.time_created} | Target User: {log.target_user_name or ''} | Domain: {log.subject_domain_name or ''}</div>"
        elif log_type == "System":
            return f"<div class='modal-row'><span class='modal-label'>[System]</span> Event: {log.event_id} | Time: {log.time_created} | Provider: {log.provider_name or ''}</div>"
        return ""

    has_any = False
    for log_type in ["Sysmon", "Application", "Security", "System"]:
        logs = logs_by_type[log_type]
        if logs:
            has_any = True
            html += f"<div class='modal-row'><b>Recent {log_type} Logs:</b></div>"
            for log in logs[:5]:
                html += log_row(log, log_type)
    if not has_any:
        html += "<div class='modal-row text-gray-400'>No logs found for this user.</div>"
    return html

@logs_bp.route('/alerts', methods=['GET'])
def get_recent_alerts():
    logs = SecurityLog.query.order_by(SecurityLog.time_created.desc()).limit(10).all()
    items = []
    for log in logs:
        user = log.subject_user_name or "Unknown"
        target_user = log.target_user_name or "Unknown"
        domain = log.subject_domain_name or "Unknown"
        computer = log.computer or "Unknown"
        event_id = log.event_id or ""
        time_str = log.time_created.strftime('%Y-%m-%d %H:%M:%S') if log.time_created else ""
        details_preview = ""
        # Compose a short preview from available fields
        if hasattr(log, "caller_process_name") and log.caller_process_name:
            details_preview += f"Process: <span class='text-blue-300'>{log.caller_process_name}</span> "
        if hasattr(log, "target_domain_name") and log.target_domain_name:
            details_preview += f"Target Domain: <span class='text-blue-300'>{log.target_domain_name}</span> "
        if hasattr(log, "target_sid") and log.target_sid:
            details_preview += f"Target SID: <span class='text-blue-300'>{log.target_sid}</span> "
        if not details_preview:
            details_preview = "<span class='text-gray-400'>No extra details</span>"

        items.append(f"""
        <li class="flex flex-col gap-1 bg-gray-800 rounded-lg px-4 py-3 shadow hover-raise cursor-pointer" data-alert-id="{log.id}">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <i class="fa-solid fa-triangle-exclamation text-yellow-400 text-xl"></i>
              <span class="text-yellow-300 font-semibold">Event {event_id}</span>
              <span class="text-gray-400 text-xs ml-2">{time_str}</span>
            </div>
            <button class="ml-2 px-2 py-1 rounded bg-blue-700 text-white text-xs font-semibold hover:bg-blue-600 transition"
              onclick="event.stopPropagation(); showSecurityLogDetail({log.id});">View</button>
          </div>
          <div class="flex flex-wrap gap-x-4 gap-y-1 mt-1 text-sm">
            <span class="text-gray-300">Computer: <span class="text-blue-300">{computer}</span></span>
            <span class="text-gray-300">Subject: <span class="text-green-300">{user}</span></span>
            <span class="text-gray-300">Target: <span class="text-green-200">{target_user}</span></span>
            <span class="text-gray-300">Domain: <span class="text-purple-300">{domain}</span></span>
          </div>
          <div class="mt-1 text-xs text-gray-400">{details_preview}</div>
        </li>
        """)
    return render_template_string('<ul id="recent-alerts" class="space-y-3">\n' + '\n'.join(items) + '\n</ul>')

@logs_bp.route('/security/alert/<int:alert_id>', methods=['GET'])
def get_security_alert_detail(alert_id):
    log = SecurityLog.query.get_or_404(alert_id)
    html = f"""
    <div class="modal-title">Security Alert Details</div>
    <div class="modal-row"><span class="modal-label">Event ID:</span> {log.event_id}</div>
    <div class="modal-row"><span class="modal-label">Time:</span> {log.time_created}</div>
    <div class="modal-row"><span class="modal-label">Computer:</span> {log.computer}</div>
    <div class="modal-row"><span class="modal-label">Subject User:</span> {log.subject_user_name or ''}</div>
    <div class="modal-row"><span class="modal-label">Target User:</span> {log.target_user_name or ''}</div>
    <div class="modal-row"><span class="modal-label">Domain:</span> {log.subject_domain_name or ''}</div>
    <div class="modal-row"><span class="modal-label">Caller Process:</span> {log.caller_process_name or ''}</div>
    """
    return html


@logs_bp.route('/<string:log_type>/<int:log_id>', methods=['GET'])
def get_log_detail_by_type(log_type, log_id):
    """Generic endpoint that maps log type names to the appropriate handler"""
    # Map the log type name (from class name) to the correct endpoint handler
    type_map = {
        'sysmonlog': get_sysmon_log_detail,
        'applicationlog': get_application_log_detail,
        'securitylog': get_security_log_detail,
        'systemlog': get_system_log_detail
    }

    # Get the appropriate handler function or 404 if not found
    handler = type_map.get(log_type.lower())
    if handler:
        return handler(log_id)
    else:
        # Try direct mapping as fallback
        direct_map = {
            'sysmon': get_sysmon_log_detail,
            'application': get_application_log_detail,
            'security': get_security_log_detail,
            'system': get_system_log_detail
        }
        handler = direct_map.get(log_type.lower())
        if handler:
            return handler(log_id)

    # If we get here, no handler was found
    from flask import abort
    abort(404, f"Log type '{log_type}' not found")