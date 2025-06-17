from flask import Blueprint, request, jsonify
import xml.etree.ElementTree as ET
from datetime import datetime
from app.db import db
import re

from app.models.logs import SysmonLog

logs_bp = Blueprint('logs', __name__, url_prefix='/api/logs')

@logs_bp.route('/sysmon', methods=['POST'], strict_slashes=False)
def sysmon_logs():
    try:
        # Get raw XML data from the request, handling invalid UTF-8 bytes
        raw_data = request.data.decode('utf-8', errors='replace')
        print("[API] Raw XML Data (Before Sanitization):", raw_data)

        # Sanitize the raw XML data to remove invalid characters
        sanitized_data = re.sub(r'[^\x09\x0A\x0D\x20-\x7F]', '', raw_data)
        print("[API] Raw XML Data (After Sanitization):", sanitized_data)

        # Parse the sanitized XML data with namespace handling
        root = ET.fromstring(sanitized_data)
        namespace = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        # Extract relevant fields from the XML
        event_data = {
            "event_id": int(root.findtext(".//ns:EventID", namespaces=namespace) or 0),
            "time_created": datetime.fromisoformat(
                root.find(".//ns:TimeCreated", namespaces=namespace).attrib.get("SystemTime").replace('Z', '+00:00')
            ),
            "computer": root.findtext(".//ns:Computer", namespaces=namespace) or "Unknown",
            "process_guid": root.findtext(".//ns:Data[@Name='ProcessGuid']", namespaces=namespace) or "Unknown",
            "process_id": int(root.findtext(".//ns:Data[@Name='ProcessId']", namespaces=namespace) or 0),
            "image": root.findtext(".//ns:Data[@Name='Image']", namespaces=namespace) or "Unknown",
            "image_loaded": root.findtext(".//ns:Data[@Name='ImageLoaded']", namespaces=namespace) or "Unknown",
            "file_version": root.findtext(".//ns:Data[@Name='FileVersion']", namespaces=namespace) or "Unknown",
            "description": root.findtext(".//ns:Data[@Name='Description']", namespaces=namespace) or "Unknown",
            "product": root.findtext(".//ns:Data[@Name='Product']", namespaces=namespace) or "Unknown",
            "company": root.findtext(".//ns:Data[@Name='Company']", namespaces=namespace) or "Unknown",
            "original_file_name": root.findtext(".//ns:Data[@Name='OriginalFileName']",
                                                namespaces=namespace) or "Unknown",
            "hashes": root.findtext(".//ns:Data[@Name='Hashes']", namespaces=namespace) or "Unknown",
            "signed": root.findtext(".//ns:Data[@Name='Signed']", namespaces=namespace) == 'true',
            "signature": root.findtext(".//ns:Data[@Name='Signature']", namespaces=namespace) or "Unknown",
            "signature_status": root.findtext(".//ns:Data[@Name='SignatureStatus']", namespaces=namespace) or "Unknown",
            "user": root.findtext(".//ns:Data[@Name='User']", namespaces=namespace) or "Unknown",
            "rule_name": root.findtext(".//ns:Data[@Name='RuleName']", namespaces=namespace) or "Unknown",
        }

        print("[API] Extracted Event Data:", event_data)

        # Create a SysmonLog object
        log = SysmonLog(
            event_id=event_data["event_id"],
            time_created=event_data["time_created"],
            computer=event_data["computer"],
            process_guid=event_data["process_guid"],
            process_id=event_data["process_id"],
            image=event_data["image"],
            image_loaded=event_data["image_loaded"],
            file_version=event_data["file_version"],
            description=event_data["description"],
            product=event_data["product"],
            company=event_data["company"],
            original_file_name=event_data["original_file_name"],
            hashes=event_data["hashes"],
            signed=event_data["signed"],
            signature=event_data["signature"],
            signature_status=event_data["signature_status"],
            user=event_data["user"],
            rule_name=event_data["rule_name"],
        )

        # Save the log to the database
        db.session.add(log)
        db.session.commit()

        # Return a success response
        return jsonify({"message": "Log saved successfully"}), 201

    except ET.ParseError as e:
        print(f"[API] XML Parse Error: {e}")
        return jsonify({"error": f"Failed to parse XML: {str(e)}"}), 400
    except Exception as e:
        print(f"[API] General Error: {e}")
        return jsonify({"error": str(e)}), 500
