from flask import Blueprint, request, jsonify
import xml.etree.ElementTree as ET
from datetime import datetime
from app.db import db
import re

from app.models.logs import SysmonLog, ApplicationLog, SecurityLog

logs_bp = Blueprint('logs', __name__, url_prefix='/api/logs')

def sanitize_xml_data(raw_data):
    """Remove invalid XML characters from raw data."""
    return re.sub(r'[^\x09\x0A\x0D\x20-\x7F]', '', raw_data)

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

@logs_bp.route('/sysmon', methods=['POST'], strict_slashes=False)
def sysmon_logs():
    try:
        raw_data = request.data.decode('utf-8', errors='replace')
        print("[API] Raw XML Data (Before Sanitization):", raw_data)
        sanitized_data = sanitize_xml_data(raw_data)
        print("[API] Raw XML Data (After Sanitization):", sanitized_data)
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
        print("[API] Extracted Event Data:", event_data)
        log = SysmonLog(**event_data)
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Log saved successfully"}), 201
    except ET.ParseError as e:
        print(f"[API] XML Parse Error: {e}")
        return jsonify({"error": f"Failed to parse XML: {str(e)}"}), 400
    except Exception as e:
        print(f"[API] General Error: {e}")
        return jsonify({"error": str(e)}), 500

@logs_bp.route('/application', methods=['POST'], strict_slashes=False)
def application_logs():
    try:
        raw_data = request.data.decode('utf-8', errors='replace')
        print("[API] Raw XML Data (Before Sanitization):", raw_data)
        sanitized_data = sanitize_xml_data(raw_data)
        print("[API] Raw XML Data (After Sanitization):", sanitized_data)
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
        print("[API] Extracted Application Event Data:", event_data)
        log = ApplicationLog(**event_data)
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Application log saved successfully"}), 201
    except ET.ParseError as e:
        print(f"[API] XML Parse Error: {e}")
        return jsonify({"error": f"Failed to parse XML: {str(e)}"}), 400
    except Exception as e:
        print(f"[API] General Error: {e}")
        return jsonify({"error": str(e)}), 500

@logs_bp.route('/security', methods=['POST'], strict_slashes=False)
def security_logs():
    try:
        raw_data = request.data.decode('utf-8', errors='replace')
        print("[API] Raw XML Data (Before Sanitization):", raw_data)
        sanitized_data = sanitize_xml_data(raw_data)
        print("[API] Raw XML Data (After Sanitization):", sanitized_data)
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
        print("[API] Extracted Security Event Data:", event_data)
        log = SecurityLog(**event_data)
        db.session.add(log)
        db.session.commit()
        return jsonify({"message": "Security log saved successfully"}), 201
    except ET.ParseError as e:
        print(f"[API] XML Parse Error: {e}")
        return jsonify({"error": f"Failed to parse XML: {str(e)}"}), 400
    except Exception as e:
        print(f"[API] General Error: {e}")
        return jsonify({"error": str(e)}), 500