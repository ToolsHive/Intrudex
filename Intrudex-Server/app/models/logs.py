from app.db import db


class ClientHost(db.Model):
    __tablename__ = 'client_hosts'
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(128), unique=True, nullable=False, index=True)
    # Optionally, add more metadata fields (e.g., description, registered_at)
    # description = db.Column(db.String(256))
    # registered_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ClientHost {self.id} - {self.hostname}>'

class SysmonLog(db.Model):
    __tablename__ = 'sysmon_logs'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer)
    time_created = db.Column(db.DateTime)
    computer = db.Column(db.String(255))
    process_guid = db.Column(db.String(100))
    process_id = db.Column(db.Integer)
    image = db.Column(db.String(500))
    image_loaded = db.Column(db.String(500))
    file_version = db.Column(db.String(255))
    description = db.Column(db.String(255))
    product = db.Column(db.String(255))
    company = db.Column(db.String(255))
    original_file_name = db.Column(db.String(255))
    hashes = db.Column(db.String(500))
    signed = db.Column(db.Boolean)
    signature = db.Column(db.String(255))
    signature_status = db.Column(db.String(50))
    user = db.Column(db.String(255))
    rule_name = db.Column(db.String(255))
    client_id = db.Column(db.Integer, db.ForeignKey('client_hosts.id'), index=True)
    client = db.relationship('ClientHost', backref='sysmon_logs')

    def __repr__(self):
        return f'<SysmonLog {self.id} - {self.image} - {self.client.hostname if self.client else "NoHost"}>'

class ApplicationLog(db.Model):
    __tablename__ = 'application_logs'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, nullable=False)
    time_created = db.Column(db.DateTime, nullable=False)
    computer = db.Column(db.String(256), nullable=False)
    process_guid = db.Column(db.String(128), nullable=False)
    process_id = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(512), nullable=False)
    target_object = db.Column(db.String(1024), nullable=False)
    details = db.Column(db.Text, nullable=True)
    event_type = db.Column(db.String(128), nullable=False)
    user = db.Column(db.String(256), nullable=False)
    rule_name = db.Column(db.String(256), nullable=True)
    client_id = db.Column(db.Integer, db.ForeignKey('client_hosts.id'), index=True)
    client = db.relationship('ClientHost', backref='application_logs')

    def __repr__(self):
        return f'<ApplicationLog {self.id} - {self.image} - {self.client.hostname if self.client else "NoHost"}>'

class SecurityLog(db.Model):
    __tablename__ = 'security_logs'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, nullable=False)
    time_created = db.Column(db.DateTime, nullable=False)
    computer = db.Column(db.String(255), nullable=False)
    target_user_name = db.Column(db.String(255), nullable=True)
    target_domain_name = db.Column(db.String(255), nullable=True)
    target_sid = db.Column(db.String(255), nullable=True)
    subject_user_sid = db.Column(db.String(255), nullable=True)
    subject_user_name = db.Column(db.String(255), nullable=True)
    subject_domain_name = db.Column(db.String(255), nullable=True)
    subject_logon_id = db.Column(db.String(255), nullable=True)
    caller_process_id = db.Column(db.String(255), nullable=True)
    caller_process_name = db.Column(db.String(512), nullable=True)
    client_id = db.Column(db.Integer, db.ForeignKey('client_hosts.id'), index=True)
    client = db.relationship('ClientHost', backref='security_logs')

    def __repr__(self):
        return f'<SecurityLog {self.id} - {self.event_id} - {self.client.hostname if self.client else "NoHost"}>'

class SystemLog(db.Model):
    __tablename__ = 'system_logs'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, nullable=False)
    time_created = db.Column(db.DateTime, nullable=False)
    computer = db.Column(db.String(255), nullable=False)
    provider_name = db.Column(db.String(255), nullable=True)
    provider_guid = db.Column(db.String(64), nullable=True)
    event_source_name = db.Column(db.String(255), nullable=True)
    event_record_id = db.Column(db.Integer, nullable=True)
    process_id = db.Column(db.Integer, nullable=True)
    thread_id = db.Column(db.Integer, nullable=True)
    user_id = db.Column(db.String(128), nullable=True)
    event_data = db.Column(db.JSON, nullable=True)
    client_id = db.Column(db.Integer, db.ForeignKey('client_hosts.id'), index=True)
    client = db.relationship('ClientHost', backref='system_logs')

    def __repr__(self):
        return f'<SystemLog {self.id} - {self.event_id} - {self.client.hostname if self.client else "NoHost"}>'
