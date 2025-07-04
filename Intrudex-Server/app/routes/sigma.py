import os
import yaml
import uuid
import time
import json
import shutil
import secrets
import requests
import tempfile
import threading
import ruamel.yaml
from datetime import datetime
from dotenv import find_dotenv, set_key, dotenv_values
from flask import Blueprint, render_template, abort, request, send_file, redirect, url_for, flash, jsonify

# Blueprint and constants
sigma_bp = Blueprint('sigma', __name__, url_prefix='/sigma')
SIGMA_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'Sigma'))
CUSTOM_FOLDER = os.path.join(SIGMA_ROOT, 'Custom')
SETTINGS_FILE = os.path.join(os.path.dirname(__file__), 'sigma_settings.json')
DOTENV_PATH = find_dotenv()

_rules_cache = {'data': [], 'timestamp': 0}
_rules_lock = threading.Lock()

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


def load_settings():
    # Load JSON settings
    try:
        with open(SETTINGS_FILE, 'r') as f:
            settings = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        settings = {}

    # Load .env settings
    env_values = dotenv_values(DOTENV_PATH) if DOTENV_PATH else {}

    # Set defaults for JSON-based settings
    defaults = {
        "include": [], "exclude": [], "auto_reload": False,
        "show_hidden": False, "sync_interval": 60,
        "api_enabled": False, "api_key": "", "client_sync_frequency": 300,
        "ai_api_key": "", "ai_provider": "openai", "ai_model": "gpt-3.5-turbo"
    }
    for key, value in defaults.items():
        settings.setdefault(key, value)

    # Add .env values to the settings dict for the template
    settings['FLASK_RUN_HOST'] = env_values.get('FLASK_RUN_HOST', '127.0.0.1')
    settings['FLASK_RUN_PORT'] = env_values.get('FLASK_RUN_PORT', '80')
    settings['FLASK_DEBUG'] = env_values.get('FLASK_DEBUG', '1') == '1'
    settings['DATABASE_URL'] = env_values.get('DATABASE_URL', 'sqlite:///intrudex.sqlite3')
    settings['Mode'] = env_values.get('Mode', 'development')
    settings['SECRET_KEY'] = env_values.get('SECRET_KEY', '')
    settings['SQLALCHEMY_TRACK_MODIFICATIONS'] = env_values.get('SQLALCHEMY_TRACK_MODIFICATIONS', 'False').lower() in ('true', '1')

    return settings


def _save_settings_to_file(data):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def build_sigma_tree_for_settings():
    """Return a tree for settings UI (folders only, with children)."""
    def walk(dir_path, rel_path=''):
        entries = []
        try:
            # List only directories
            items = sorted([d for d in os.listdir(dir_path) if os.path.isdir(os.path.join(dir_path, d))], key=lambda x: x.lower())
        except Exception:
            return entries
        for item in items:
            abs_item = os.path.join(dir_path, item)
            rel_item = os.path.join(rel_path, item) if rel_path else item
            children = walk(abs_item, rel_item)
            entries.append({
                'name': item,
                'path': rel_item.replace("\\", "/"),
                'children': children
            })
        return entries
    return walk(SIGMA_ROOT)

@sigma_bp.route('/settings/folders')
def sigma_settings_folders():
    # Returns the folder tree as JSON for the settings UI
    return jsonify(build_sigma_tree_for_settings())

@sigma_bp.route('/settings', methods=['GET'])
def sigma_settings():
    settings = load_settings()
    return render_template("sigma/settings.html", settings=settings)


@sigma_bp.route('/settings', methods=['POST'])
def save_settings():
    # Save JSON-based settings
    json_data = {
        "include": request.form.getlist('include[]'),
        "exclude": request.form.getlist('exclude[]'),
        "auto_reload": 'auto_reload' in request.form,
        "show_hidden": 'show_hidden' in request.form,
        "sync_interval": int(request.form.get('sync_interval', 60)),
        "api_enabled": 'api_enabled' in request.form,
        "client_sync_frequency": int(request.form.get('client_sync_frequency', 300)),
        "api_key": load_settings().get('api_key', ''), # Preserve existing API key
        "ai_api_key": request.form.get('ai_api_key', ''),
        "ai_provider": request.form.get('ai_provider', 'openai'),
        "ai_model": request.form.get('ai_model', 'gpt-3.5-turbo')
    }
    _save_settings_to_file(json_data)

    # Save .env settings
    if DOTENV_PATH:
        set_key(DOTENV_PATH, "FLASK_RUN_HOST", request.form.get('FLASK_RUN_HOST', '127.0.0.1'))
        set_key(DOTENV_PATH, "FLASK_RUN_PORT", request.form.get('FLASK_RUN_PORT', '80'))
        set_key(DOTENV_PATH, "FLASK_DEBUG", '1' if 'FLASK_DEBUG' in request.form else '0')
        set_key(DOTENV_PATH, "DATABASE_URL", request.form.get('DATABASE_URL', 'sqlite:///intrudex.sqlite3'))
        set_key(DOTENV_PATH, "Mode", request.form.get('Mode', 'development'))
        set_key(DOTENV_PATH, "SECRET_KEY", request.form.get('SECRET_KEY', ''))
        set_key(DOTENV_PATH, "SQLALCHEMY_TRACK_MODIFICATIONS", 'True' if 'SQLALCHEMY_TRACK_MODIFICATIONS' in request.form else 'False')

    flash("Settings updated successfully. Application restart is required for some changes to take effect.", "success")
    return redirect(url_for("sigma.sigma_settings"))

@sigma_bp.route('/settings/generate-api-key', methods=['POST'])
def generate_api_key():
    settings = load_settings()
    new_key = secrets.token_hex(32)
    settings['api_key'] = new_key
    _save_settings_to_file(settings)
    return jsonify({'api_key': new_key})

@sigma_bp.route('/settings/generate-secret-key', methods=['POST'])
def generate_secret_key():
    new_key = secrets.token_hex(24)
    return jsonify({'secret_key': new_key})

@sigma_bp.route('/api/rules')
def api_rules():
    settings = load_settings()
    if not settings.get('api_enabled'):
        return jsonify({'error': 'API is disabled'}), 403

    provided_key = request.headers.get('X-API-Key')
    if not provided_key or not secrets.compare_digest(provided_key, settings.get('api_key', '')):
        return jsonify({'error': 'Unauthorized'}), 401

    # Return the filtered file/folder tree structure
    sigma_tree = build_sigma_tree()
    response_data = {
        'timestamp': time.time(),
        'tree': sigma_tree
    }
    return jsonify(response_data)

@sigma_bp.route('/api/rule/<path:rule_path>')
def api_rule_content(rule_path):
    settings = load_settings()
    if not settings.get('api_enabled'):
        return jsonify({'error': 'API is disabled'}), 403

    provided_key = request.headers.get('X-API-Key')
    if not provided_key or not secrets.compare_digest(provided_key, settings.get('api_key', '')):
        return jsonify({'error': 'Unauthorized'}), 401

    safe_path = os.path.normpath(os.path.join(SIGMA_ROOT, rule_path))
    if not safe_path.startswith(SIGMA_ROOT) or not os.path.isfile(safe_path):
        return jsonify({'error': 'Rule not found'}), 404

    try:
        with open(safe_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({'path': rule_path, 'content': content})
    except Exception as e:
        return jsonify({'error': f'Could not read rule: {e}'}), 500

@sigma_bp.route('/generate-ai-rule', methods=['POST'])
def generate_ai_rule():
    settings = load_settings()
    
    # Check if AI is configured
    ai_api_key = settings.get('ai_api_key', '').strip()
    if not ai_api_key:
        return jsonify({'error': 'AI API key not configured. Please set it in settings.'}), 400
    
    data = request.get_json()
    if not data or not data.get('prompt'):
        return jsonify({'error': 'No prompt provided'}), 400
    
    prompt = data['prompt'].strip()
    ai_provider = settings.get('ai_provider', 'openai')
    ai_model = settings.get('ai_model', 'gpt-3.5-turbo')
    
    try:
        # Generate UUID and current date
        rule_uuid = str(uuid.uuid4())
        current_date = datetime.now().strftime('%Y/%m/%d')
        
        if ai_provider == 'openai':
            rule_content = generate_with_openai(prompt, ai_api_key, ai_model, rule_uuid, current_date)
        elif ai_provider == 'anthropic':
            rule_content = generate_with_anthropic(prompt, ai_api_key, ai_model, rule_uuid, current_date)
        else:
            return jsonify({'error': f'Unsupported AI provider: {ai_provider}'}), 400
        
        return jsonify({'rule': rule_content})
    
    except Exception as e:
        return jsonify({'error': f'AI generation failed: {str(e)}'}), 500

def generate_with_openai(prompt, api_key, model, rule_uuid, current_date):
    """Generate SIGMA rule using OpenAI API"""
    
    system_prompt = f"""
You are an expert cybersecurity analyst specialized in creating SIGMA detection rules. 
Create a valid SIGMA rule in YAML format based on the user's description.

Use this UUID: {rule_uuid}
Use this date: {current_date}

Rules should follow this structure:
title: [Brief descriptive title]
id: {rule_uuid}
description: [Detailed description of what this rule detects]
status: experimental
author: AI Generated
date: {current_date}
logsource:
  category: [appropriate category like process_creation, network_connection, etc.]
  product: [windows/linux/etc.]
  service: [if applicable]
detection:
  selection:
    [appropriate fields and values]
  condition: selection
level: [low/medium/high/critical]
tags:
  - [relevant MITRE ATT&CK techniques]
  - [other relevant tags]
falsepositives:
  - [potential false positive scenarios]

Only return the YAML content, no additional explanations or markdown formatting.
"""
    
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }
    
    payload = {
        'model': model,
        'messages': [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': prompt}
        ],
        'temperature': 0.3,
        'max_tokens': 1500
    }
    
    response = requests.post(
        'https://api.openai.com/v1/chat/completions',
        headers=headers,
        json=payload,
        timeout=30
    )
    
    if response.status_code != 200:
        raise Exception(f'OpenAI API error: {response.status_code} - {response.text}')
    
    result = response.json()
    return result['choices'][0]['message']['content'].strip()

def generate_with_anthropic(prompt, api_key, model, rule_uuid, current_date):
    """Generate SIGMA rule using Anthropic Claude API"""
    
    system_prompt = f"""
You are an expert cybersecurity analyst specialized in creating SIGMA detection rules. 
Create a valid SIGMA rule in YAML format based on the user's description.

Use this UUID: {rule_uuid}
Use this date: {current_date}

Rules should follow this structure:
title: [Brief descriptive title]
id: {rule_uuid}
description: [Detailed description of what this rule detects]
status: experimental
author: AI Generated
date: {current_date}
logsource:
  category: [appropriate category like process_creation, network_connection, etc.]
  product: [windows/linux/etc.]
  service: [if applicable]
detection:
  selection:
    [appropriate fields and values]
  condition: selection
level: [low/medium/high/critical]
tags:
  - [relevant MITRE ATT&CK techniques]
  - [other relevant tags]
falsepositives:
  - [potential false positive scenarios]

Only return the YAML content, no additional explanations or markdown formatting.
"""
    
    headers = {
        'x-api-key': api_key,
        'Content-Type': 'application/json',
        'anthropic-version': '2023-06-01'
    }
    
    payload = {
        'model': model,
        'max_tokens': 1500,
        'temperature': 0.3,
        'system': system_prompt,
        'messages': [
            {'role': 'user', 'content': prompt}
        ]
    }
    
    response = requests.post(
        'https://api.anthropic.com/v1/messages',
        headers=headers,
        json=payload,
        timeout=30
    )
    
    if response.status_code != 200:
        raise Exception(f'Anthropic API error: {response.status_code} - {response.text}')
    
    result = response.json()
    return result['content'][0]['text'].strip()
