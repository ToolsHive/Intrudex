from app.db import db


class SysmonLog(db.Model):
    __tablename__: str = 'sysmon_logs'

    id = db.Column(db.Integer, primary_key=True)  # Auto-incrementing primary key
    event_id = db.Column(db.Integer)  # EventID (e.g., 7)
    time_created = db.Column(db.DateTime)  # TimeCreated (SystemTime)
    computer = db.Column(db.String(255))  # Computer name
    process_guid = db.Column(db.String(100))  # ProcessGuid
    process_id = db.Column(db.Integer)  # ProcessId
    image = db.Column(db.String(500))  # Path to the executable (Image)
    image_loaded = db.Column(db.String(500))  # Loaded DLL or file
    file_version = db.Column(db.String(255))  # FileVersion
    description = db.Column(db.String(255))  # Description
    product = db.Column(db.String(255))  # Product
    company = db.Column(db.String(255))  # Company
    original_file_name = db.Column(db.String(255))  # OriginalFileName
    hashes = db.Column(db.String(500))  # Hashes
    signed = db.Column(db.Boolean)  # Signed (true/false)
    signature = db.Column(db.String(255))  # Signature
    signature_status = db.Column(db.String(50))  # SignatureStatus (Valid/Invalid)
    user = db.Column(db.String(255))  # User running the process
    rule_name = db.Column(db.String(255))  # RuleName (usually "-")

    def __repr__(self):
        return f'<SysmonLog {self.id} - {self.image}>'
