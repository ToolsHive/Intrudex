from flask import Blueprint, render_template, request, abort
from markupsafe import Markup, escape
from app.models.logs import SysmonLog, SystemLog, ApplicationLog, SecurityLog

view_bp = Blueprint('view', __name__, url_prefix='/view')

LOG_MODELS = {
    'sysmon': SysmonLog,
    'system': SystemLog,
    'application': ApplicationLog,
    'security': SecurityLog,
}

@view_bp.route('/')
def view_index():
    return render_template('view/index.html')

@view_bp.route('/<log_type>')
def view_log_table(log_type):
    if log_type not in LOG_MODELS:
        abort(404)
    page = int(request.args.get('page', 1))
    per_page = 10
    model = LOG_MODELS[log_type]

    # Fetch all logs from the database (no limit)
    raw_logs = model.query.order_by(model.time_created.desc()).all()

    def count_unknown_fields(log):
        unknown_count = 0
        for key, value in log.__dict__.items():
            if key.startswith('_'):
                continue
            if value is None or (isinstance(value, str) and value.strip().lower() == "unknown"):
                unknown_count += 1
        return unknown_count

    # Sort logs: those with fewer "unknown" fields come first, then by time_created desc
    sorted_logs = sorted(
        raw_logs,
        key=lambda log: (count_unknown_fields(log), -(log.time_created.timestamp() if getattr(log, "time_created", None) else 0))
    )

    # Paginate after sorting
    total = len(sorted_logs)
    start = (page - 1) * per_page
    end = start + per_page
    logs = sorted_logs[start:end]

    # Fake a pagination object for template compatibility
    class Pagination:
        def __init__(self, page, per_page, total):
            self.page = page
            self.per_page = per_page
            self.total = total
            self.pages = (total + per_page - 1) // per_page
            self.has_prev = page > 1
            self.has_next = page < self.pages
            self.prev_num = page - 1
            self.next_num = page + 1

    pagination = Pagination(page, per_page, total)
    return render_template('view/log_table.html', logs=logs, pagination=pagination, log_type=log_type)

@view_bp.route('/<log_type>/<int:log_id>')
def view_log_detail(log_type, log_id):
    if log_type not in LOG_MODELS:
        abort(404)
    model = LOG_MODELS[log_type]
    log = model.query.get_or_404(log_id)

    # Prepare a list of (label, value) for all fields, skipping private ones
    fields = []
    for key in sorted(log.__dict__):
        if key.startswith('_'):
            continue
        value = getattr(log, key)
        # Format and sanitize value
        if isinstance(value, dict):
            pretty = ""
            for k, v in value.items():
                pretty += f"<tr><td class='py-1 px-2 text-blue-200'>{escape(str(k))}</td><td class='py-1 px-2 text-gray-200'>{escape(str(v))}</td></tr>"
            value = f"<table class='min-w-full text-xs bg-gray-900 rounded mb-2'><tbody>{pretty}</tbody></table>"
        elif value is None or value == "":
            value = "<span class='text-gray-400 italic'>None</span>"
        else:
            val = str(value).strip()
            # If value looks like a CSV or repeated value, split and show as a vertical table (not ul)
            if ',' in val and not val.startswith('{') and not val.startswith('['):
                items = [escape(v.strip()) for v in val.split(',') if v.strip()]
                value = (
                    "<table class='min-w-full text-xs bg-gray-900 rounded mb-2'>"
                    "<tbody>"
                    + "".join(f"<tr><td class='py-1 px-2 text-blue-200'>Item</td><td class='py-1 px-2 text-gray-200'>{v}</td></tr>" for v in items)
                    + "</tbody></table>"
                )
            # If value is a long string with repeated words, show as a block
            elif len(val) > 60 and ' ' in val:
                value = f"<div class='bg-gray-800 rounded p-2 text-xs text-gray-200 break-words'>{escape(val)}</div>"
            else:
                value = escape(val)
                # Highlight booleans and numbers
                if value in ["True", "False"]:
                    value = f"<span class='px-2 py-0.5 rounded bg-blue-800 text-blue-200 font-mono'>{value}</span>"
                elif value.isdigit():
                    value = f"<span class='font-mono text-green-300'>{value}</span>"
        fields.append((key.replace('_', ' ').title(), value))

    # Render as a beautiful, easy-to-read table with zebra striping and clear labels
    html = f"""
    <div>
        <h2 class="text-2xl font-bold mb-4 text-blue-200 flex items-center gap-2">
            <i class="fa-solid fa-circle-info text-blue-400"></i>
            {log_type.capitalize()} Log Details
        </h2>
        <div class="rounded-xl overflow-hidden shadow border border-gray-700 bg-gray-900">
            <table class="min-w-full text-sm text-left">
                <tbody>
                    {''.join(
                        f'<tr class="{"bg-gray-800" if i%2 else ""} hover:bg-gray-700 transition">'
                        f'<td class="py-2 px-3 font-semibold text-blue-300 w-1/3">{label}</td>'
                        f'<td class="py-2 px-3">{value}</td></tr>'
                        for i, (label, value) in enumerate(fields)
                    )}
                </tbody>
            </table>
        </div>
    </div>
    """
    return html
