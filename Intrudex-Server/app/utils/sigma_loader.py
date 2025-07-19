# app/utils/sigma_loader.py
import os
import yaml
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import defaultdict
from datetime import datetime, timedelta

# Import Sigma components
from sigma.rule import SigmaRule
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline

# Get the Sigma root directory
SIGMA_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'Sigma'))
SETTINGS_FILE = os.path.join(os.path.dirname(__file__), '..', 'routes', 'sigma_settings.json')


class MemoryBackend:
    """
    A simple in-memory backend for Sigma rule matching.
    This serves as a replacement for the missing sigma.backends.database module.
    """

    def __init__(self, pipeline: ProcessingPipeline):
        self.pipeline = pipeline

    def convert_rule(self, rule):
        """Convert a Sigma rule to a format suitable for matching logs"""
        return CompiledRule(rule)


class CompiledRule:
    """A compiled rule that can match against log entries"""

    def __init__(self, rule: SigmaRule):
        self.rule = rule
        self.title = rule.title
        self.id = rule.id
        self.level = rule.level
        self.tags = rule.tags

    def match(self, log_dict: Dict[str, Any]) -> bool:
        """Match a log dictionary against this rule (more flexible)"""
        try:
            detection_items = list(self._get_detection_items())
            if not detection_items:
                return False
            
            # For debugging
            print(f"Matching rule {self.title} against log...")
            print(f"Detection items: {detection_items}")
            print(f"Log dict: {json.dumps(log_dict, default=str)[:200]}...")
            
            matches = 0
            total_items = len(detection_items)
            
            for field_name, field_value in detection_items:
                log_value = self._get_nested_value(log_dict, field_name)
                if log_value is None:
                    print(f"Field {field_name} not found in log")
                    continue

                print(f"Checking field {field_name}: log_value={log_value}, rule_value={field_value}")
                
                if isinstance(field_value, list):
                    if any(self._match_value(log_value, v) for v in field_value):
                        matches += 1
                        print(f"Matched list value for {field_name}")
                else:
                    if self._match_value(log_value, field_value):
                        matches += 1
                        print(f"Matched single value for {field_name}")
            
            # Consider it a match if we have at least one matching field
            result = matches > 0
            print(f"Rule {self.title} match result: {result} (matched {matches}/{total_items} fields)")
            return result
            
        except Exception as e:
            print(f"Error in rule matching for {self.title}: {e}")
            return False

    def _get_detection_items(self):
        """Extract detection items from the rule (robust for all detection keys)"""
        if not hasattr(self.rule, 'detection') or not self.rule.detection:
            return []
        detection = self.rule.detection
        items = []
        # Sigma rules may have multiple keys in detection (selection, filter, etc.)
        if isinstance(detection, dict):
            for key, value in detection.items():
                if isinstance(value, dict):
                    items.extend(value.items())
                elif isinstance(value, list):
                    # List of dicts (OR logic)
                    for v in value:
                        if isinstance(v, dict):
                            items.extend(v.items())
        # Fallback to detection_items if available
        if hasattr(detection, 'detection_items'):
            for item in detection.detection_items:
                if hasattr(item, 'field_value_map'):
                    items.extend(item.field_value_map.items())
        return items


    def _get_nested_value(self, d: Dict[str, Any], key: str):
        """Get a nested value from a dictionary using dot notation"""
        parts = key.split('.')
        value = d
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return None
        return value

    def _match_value(self, log_value, rule_value):
        """Match a log value against a rule value"""
        # String matching with wildcard support
        if isinstance(rule_value, str) and isinstance(log_value, str):
            if rule_value.startswith('*') and rule_value.endswith('*'):
                return rule_value[1:-1].lower() in log_value.lower()
            elif rule_value.startswith('*'):
                return log_value.lower().endswith(rule_value[1:].lower())
            elif rule_value.endswith('*'):
                return log_value.lower().startswith(rule_value[:-1].lower())
            else:
                return log_value.lower() == rule_value.lower()
        # Direct comparison for other types
        return log_value == rule_value


def load_settings():
    """Load Sigma settings from the settings file"""
    try:
        with open(SETTINGS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "include": [],
            "exclude": [],
            "auto_reload": False,
            "show_hidden": False
        }


# Global cache for rules
_rule_cache = {
    'rules': None,
    'last_updated': None,
    'cache_duration': timedelta(minutes=60)  # Cache rules for 60 minutes
}

def load_sigma_rules(force_reload=False) -> List[SigmaRule]:
    """
    Load Sigma rules from the file system with caching.
    Returns a list of SigmaRule objects.
    """
    global _rule_cache
    
    # Check if we have valid cached rules
    current_time = datetime.now()
    if not force_reload and _rule_cache['rules'] is not None:
        if _rule_cache['last_updated'] + _rule_cache['cache_duration'] > current_time:
            return _rule_cache['rules']
    
    # If we reach here, we need to load the rules
    settings = load_settings()
    include_dirs = settings.get("include", [])
    exclude_dirs = settings.get("exclude", [])
    
    rules = []
    
    # If no include dirs specified, include everything
    if not include_dirs:
        include_dirs = [""]
        
    # Process each include directory
    for include_dir in include_dirs:
        dir_path = os.path.join(SIGMA_ROOT, include_dir)
        if not os.path.exists(dir_path):
            continue

        for root, _, files in os.walk(dir_path):
            # Skip excluded directories
            if any(excluded in root for excluded in exclude_dirs):
                continue

            for file in files:
                if file.endswith(('.yml', '.yaml')):
                    try:
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r', encoding='utf-8') as f:
                            rule_content = yaml.safe_load(f)

                        # Skip files that don't contain valid rules
                        if not isinstance(rule_content, dict) or 'detection' not in rule_content:
                            continue

                        # Create a SigmaRule object
                        rule = SigmaRule.from_dict(rule_content)
                        rules.append(rule)
                    except Exception as e:
                        print(f"Error loading rule {file}: {str(e)}")

    # Update cache
    _rule_cache['rules'] = rules
    _rule_cache['last_updated'] = current_time
    
    return rules

def invalidate_rule_cache():
    """Force reload of rules on next request"""
    global _rule_cache
    _rule_cache['rules'] = None
    _rule_cache['last_updated'] = None