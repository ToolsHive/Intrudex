import os
import yaml
import shutil
import tempfile
import ruamel.yaml
from flask import Blueprint, render_template, abort, request, send_file, redirect, url_for, flash

sigma_bp = Blueprint('sigma', __name__, url_prefix='/sigma')
SIGMA_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'Sigma'))
CUSTOM_FOLDER = os.path.join(SIGMA_ROOT, 'Custom')

def build_sigma_tree():
    """
    Returns a list of dicts representing the Sigma folder/file tree.
    Each dict: {type: 'folder'|'file', name: str, path: str, children: [list]}
    """
    def walk(dir_path, rel_path=''):
        entries = []
        try:
            items = sorted(os.listdir(dir_path), key=lambda x: (not os.path.isdir(os.path.join(dir_path, x)), x.lower()))
        except Exception:
            return entries
        for item in items:
            abs_item = os.path.join(dir_path, item)
            rel_item = os.path.join(rel_path, item) if rel_path else item
            if os.path.isdir(abs_item):
                children = walk(abs_item, rel_item)
                entries.append({
                    'type': 'folder',
                    'name': item,
                    'path': rel_item.replace("\\", "/"),
                    'children': children
                })
            elif item.endswith(('.yml', '.yaml')):
                entries.append({
                    'type': 'file',
                    'name': item,
                    'path': rel_item.replace("\\", "/")
                })
        return entries
    return walk(SIGMA_ROOT)

def fuzzy_match(text, query):
    """Returns True if all chars of query appear in order in text (case-insensitive)."""
    text = text.lower()
    query = query.lower()
    t = 0
    q = 0
    while t < len(text) and q < len(query):
        if text[t] == query[q]:
            q += 1
        t += 1
    return q == len(query)

def filter_tree(tree, query):
    """Recursively filter the tree to only include folders/files matching the fuzzy query."""
    filtered = []
    for entry in tree:
        name_match = fuzzy_match(entry['name'], query)
        path_match = fuzzy_match(entry['path'], query)
        if entry['type'] == 'folder':
            children = filter_tree(entry['children'], query)
            if name_match or path_match or children:
                filtered.append({
                    **entry,
                    'children': children
                })
        elif entry['type'] == 'file':
            if name_match or path_match:
                filtered.append(entry)
    return filtered

@sigma_bp.route('/')
def sigma_index():
    sigma_tree = build_sigma_tree()
    return render_template('sigma/index.html', sigma_tree=sigma_tree)

@sigma_bp.route('/search')
def sigma_search():
    query = request.args.get('q', '').strip()
    sigma_tree = build_sigma_tree()
    filtered_tree = filter_tree(sigma_tree, query) if query else sigma_tree
    return render_template('sigma/_tree.html', sigma_tree=filtered_tree)

@sigma_bp.route('/view/<path:rule_path>')
def view_rule(rule_path):
    safe_path = os.path.normpath(os.path.join(SIGMA_ROOT, rule_path))
    if not safe_path.startswith(SIGMA_ROOT) or not os.path.isfile(safe_path):
        abort(404)
    with open(safe_path, 'r', encoding='utf-8') as f:
        content = f.read()
    return render_template('sigma/view.html', rule_path=rule_path, content=content)

@sigma_bp.route('/export/<path:folder_path>')
def export_folder(folder_path):
    safe_path = os.path.normpath(os.path.join(SIGMA_ROOT, folder_path))
    if not safe_path.startswith(SIGMA_ROOT) or not os.path.isdir(safe_path):
        abort(404)
    # Create a temporary zip file
    tmp_dir = tempfile.mkdtemp()
    zip_base = os.path.join(tmp_dir, 'export')
    shutil.make_archive(zip_base, 'zip', safe_path)
    zip_path = zip_base + '.zip'
    return send_file(zip_path, as_attachment=True, download_name=f"{os.path.basename(folder_path)}.zip")

@sigma_bp.route('/rules', methods=['GET', 'POST'])
def custom_rules():
    if request.method == 'POST':
        rule_name = request.form.get('rule_name', '').strip()
        yaml_content = request.form.get('yaml', '').strip()
        if yaml_content and rule_name:
            try:
                yaml = ruamel.yaml.YAML()
                yaml.preserve_quotes = True
                data = yaml.load(yaml_content)  # Validate YAML
                # Beautify YAML (no extra blank lines, consistent indentation)
                from io import StringIO
                buf = StringIO()
                yaml.indent(mapping=2, sequence=4, offset=2)
                yaml.dump(data, buf)
                beautified = buf.getvalue().strip()
            except Exception as e:
                flash(f'YAML Error: {e}', 'danger')
                return redirect(url_for('sigma.custom_rules'))
            if not os.path.exists(CUSTOM_FOLDER):
                os.makedirs(CUSTOM_FOLDER)
            filename = rule_name if rule_name.endswith(('.yml', '.yaml')) else rule_name + '.yml'
            file_path = os.path.join(CUSTOM_FOLDER, filename)
            if os.path.exists(file_path):
                flash('A rule with this name already exists.', 'danger')
            else:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(beautified)
                flash('Rule created successfully!', 'success')
                return redirect(url_for('sigma.custom_rules'))
        else:
            flash('Rule name and YAML content are required.', 'danger')
    # List only files in Custom
    rules = []
    if os.path.exists(CUSTOM_FOLDER):
        for fname in sorted(os.listdir(CUSTOM_FOLDER)):
            if fname.endswith(('.yml', '.yaml')):
                rules.append(fname)
    return render_template('sigma/rules.html', rules=rules)