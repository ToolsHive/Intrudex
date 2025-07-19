"""
API endpoints for progressive loading of rule details
"""
from flask import jsonify, Blueprint, request, current_app
from app.routes.sigmarules import get_compiled_rules, fetch_rule_metadata_from_sigma_repo, get_enhanced_mitre_info
from app.routes.sigmarules import calculate_comprehensive_quality_score, estimate_rule_performance
from app.routes.sigmarules import find_rule_dependencies, find_similar_rules, get_deployment_considerations
from app.routes.sigmarules import log_debug
from flask import jsonify, Blueprint, request
from app.routes.sigmarules import get_compiled_rules, fetch_rule_metadata_from_sigma_repo, get_enhanced_mitre_info
from app.routes.sigmarules import calculate_comprehensive_quality_score, estimate_rule_performance
from app.routes.sigmarules import find_rule_dependencies, find_similar_rules, get_deployment_considerations
# from app.utils.logging import log_debug
import traceback

# Create a blueprint for the API endpoints
api_bp = Blueprint('sigmarules_api', __name__, url_prefix='/sigmarules/api')

# Cache for rule data to improve performance
_rule_cache = {}

def get_rule_basic_data(rule_id):
    """Get basic rule data including title, description, and quality score"""
    try:
        # Check cache first
        if rule_id in _rule_cache and 'basic' in _rule_cache[rule_id]:
            return _rule_cache[rule_id]['basic']
            
        # Get compiled rules
        rules = get_compiled_rules()
        if not rules:
            return jsonify({'error': 'No Sigma rules are currently loaded'}), 404

        # Find the specific rule
        rule = None
        for r in rules:
            if str(getattr(r, 'id', f'rule-{hash(str(r.title))}')) == rule_id:
                rule = r
                break
        
        if not rule:
            return jsonify({'error': f'Rule with ID {rule_id} not found'}), 404

        # Extract basic rule information
        rule_title = str(getattr(rule, 'title', 'Unknown Rule'))
        rule_description = str(getattr(rule, 'description', ''))
        
        # Try to fetch enhanced metadata from Sigma repository
        enhanced_metadata = fetch_rule_metadata_from_sigma_repo(rule_title, rule_id)
        
        # Build basic rule data
        rule_data = {
            'id': rule_id,
            'title': enhanced_metadata.get('title', rule_title) if enhanced_metadata else rule_title,
            'level': enhanced_metadata.get('level', str(getattr(rule.level, 'name', 'medium') if rule.level else 'medium')) if enhanced_metadata else str(getattr(rule.level, 'name', 'medium') if rule.level else 'medium'),
            'description': enhanced_metadata.get('description', rule_description) if enhanced_metadata and enhanced_metadata.get('description') != 'No description available' else rule_description or 'No description available',
            'author': enhanced_metadata.get('author', str(getattr(rule, 'author', 'Unknown'))) if enhanced_metadata else str(getattr(rule, 'author', 'Unknown')),
            'date': enhanced_metadata.get('date', str(getattr(rule, 'date', 'Unknown'))) if enhanced_metadata else str(getattr(rule, 'date', 'Unknown')),
            'modified': enhanced_metadata.get('modified', str(getattr(rule, 'modified', 'Unknown'))) if enhanced_metadata else str(getattr(rule, 'modified', 'Unknown')),
            'status': enhanced_metadata.get('status', str(getattr(rule, 'status', 'stable'))) if enhanced_metadata else str(getattr(rule, 'status', 'stable')),
            'license': str(getattr(rule, 'license', 'Unknown')),
            'detection_complexity': ''
        }
        
        # Calculate detection complexity
        complexity_score = 0
        detection_dict = getattr(rule, 'detection', {})
        if detection_dict and isinstance(detection_dict, dict):
            keys = list(detection_dict.keys())
            condition = detection_dict.get('condition', '')
            detection_str = str(detection_dict).lower()
            
            if len(keys) > 5:
                complexity_score += 3
            elif len(keys) > 3:
                complexity_score += 2
            elif len(keys) > 1:
                complexity_score += 1
            
            if 'and' in str(condition).lower() and 'or' in str(condition).lower():
                complexity_score += 2
            elif 'and' in str(condition).lower() or 'or' in str(condition).lower():
                complexity_score += 1
            
            if any(key.startswith('filter') for key in keys):
                complexity_score += 1
            if 're:' in detection_str or 'regex:' in detection_str:
                complexity_score += 2
            if '*' in detection_str or '?' in detection_str:
                complexity_score += 1
            
            if complexity_score >= 6:
                rule_data['detection_complexity'] = 'Very Complex'
            elif complexity_score >= 4:
                rule_data['detection_complexity'] = 'Complex'
            elif complexity_score >= 2:
                rule_data['detection_complexity'] = 'Moderate'
            else:
                rule_data['detection_complexity'] = 'Simple'

        # Calculate comprehensive quality score
        quality_score, quality_factors = calculate_comprehensive_quality_score(rule_data)
        rule_data['quality_score'] = quality_score
        rule_data['quality_factors'] = quality_factors
        
        # Determine quality level
        if quality_score >= 90:
            rule_data['quality_level'] = 'exceptional'
        elif quality_score >= 75:
            rule_data['quality_level'] = 'excellent'
        elif quality_score >= 60:
            rule_data['quality_level'] = 'good'
        elif quality_score >= 40:
            rule_data['quality_level'] = 'fair'
        elif quality_score >= 20:
            rule_data['quality_level'] = 'basic'
        else:
            rule_data['quality_level'] = 'poor'
            
        # Cache the data
        if rule_id not in _rule_cache:
            _rule_cache[rule_id] = {}
        _rule_cache[rule_id]['basic'] = rule_data
        
        return rule_data
        
    except Exception as e:
        log_debug(f"Error getting basic rule data: {str(e)}")
        log_debug(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

def get_rule_mitre_data(rule_id):
    """Get MITRE ATT&CK data for a rule"""
    try:
        # Check cache first
        if rule_id in _rule_cache and 'mitre' in _rule_cache[rule_id]:
            return _rule_cache[rule_id]['mitre']
            
        # Get compiled rules
        rules = get_compiled_rules()
        if not rules:
            return jsonify({'error': 'No Sigma rules are currently loaded'}), 404

        # Find the specific rule
        rule = None
        for r in rules:
            if str(getattr(r, 'id', f'rule-{hash(str(r.title))}')) == rule_id:
                rule = r
                break
        
        if not rule:
            return jsonify({'error': f'Rule with ID {rule_id} not found'}), 404
            
        # Get enhanced metadata
        rule_title = str(getattr(rule, 'title', 'Unknown Rule'))
        enhanced_metadata = fetch_rule_metadata_from_sigma_repo(rule_title, rule_id)
        
        # Extract MITRE ATT&CK techniques
        mitre_attack = []
        rule_tags = enhanced_metadata.get('tags', getattr(rule, 'tags', [])) if enhanced_metadata else getattr(rule, 'tags', [])
        
        if rule_tags and hasattr(rule_tags, '__iter__') and not isinstance(rule_tags, str):
            try:
                for tag in rule_tags:
                    tag_str = str(tag)
                    
                    # Extract MITRE ATT&CK techniques with enhanced information
                    if tag_str.startswith('attack.'):
                        enhanced_mitre_info = get_enhanced_mitre_info(tag_str)
                        if enhanced_mitre_info:
                            mitre_attack.append(enhanced_mitre_info)
            except Exception as e:
                log_debug(f"Error processing MITRE tags: {str(e)}")
        
        result = {'mitre_attack': mitre_attack}
        
        # Cache the data
        if rule_id not in _rule_cache:
            _rule_cache[rule_id] = {}
        _rule_cache[rule_id]['mitre'] = result
        
        return result
        
    except Exception as e:
        log_debug(f"Error getting MITRE data: {str(e)}")
        log_debug(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

def get_rule_detection_data(rule_id):
    """Get detection logic for a rule"""
    try:
        # Check cache first
        if rule_id in _rule_cache and 'detection' in _rule_cache[rule_id]:
            return _rule_cache[rule_id]['detection']
            
        # Get compiled rules
        rules = get_compiled_rules()
        if not rules:
            return jsonify({'error': 'No Sigma rules are currently loaded'}), 404

        # Find the specific rule
        rule = None
        for r in rules:
            if str(getattr(r, 'id', f'rule-{hash(str(r.title))}')) == rule_id:
                rule = r
                break
        
        if not rule:
            return jsonify({'error': f'Rule with ID {rule_id} not found'}), 404
            
        # Get detection logic
        detection = getattr(rule, 'detection', {})
        
        # Generate a detection explanation
        detection_explanation = "This Sigma rule defines specific patterns and conditions that security tools should monitor for."
        
        if detection and isinstance(detection, dict):
            condition = detection.get('condition', '')
            if condition:
                if 'all of them' in str(condition):
                    detection_explanation += " All defined conditions must be met for an alert to trigger."
                elif 'any of them' in str(condition):
                    detection_explanation += " Any of the defined conditions will trigger an alert if matched."
                elif '1 of them' in str(condition):
                    detection_explanation += " At least one of the defined conditions must be met."
                
                if 'not' in str(condition).lower():
                    detection_explanation += " The rule includes exclusion conditions to reduce false positives."
                    
        # Generate detection statistics
        detection_metrics = {
            'field_count': len(detection.keys()) if detection and isinstance(detection, dict) else 0,
            'condition_complexity': len(str(detection.get('condition', '')).split()) if detection and isinstance(detection, dict) else 0,
            'has_filters': any(key.startswith('filter') for key in detection.keys()) if detection and isinstance(detection, dict) else False,
            'uses_regex': 're:' in str(detection).lower() or 'regex:' in str(detection).lower() if detection else False,
            'uses_wildcards': '*' in str(detection) or '?' in str(detection) if detection else False
        }
        
        result = {
            'detection': detection,
            'detection_explanation': detection_explanation,
            'detection_metrics': detection_metrics
        }
        
        # Cache the data
        if rule_id not in _rule_cache:
            _rule_cache[rule_id] = {}
        _rule_cache[rule_id]['detection'] = result
        
        return result
        
    except Exception as e:
        log_debug(f"Error getting detection data: {str(e)}")
        log_debug(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

def get_rule_performance_data(rule_id):
    """Get performance impact data for a rule"""
    try:
        # Check cache first
        if rule_id in _rule_cache and 'performance' in _rule_cache[rule_id]:
            return _rule_cache[rule_id]['performance']
            
        # Get basic rule data first
        rule_data = get_rule_basic_data(rule_id)
        if isinstance(rule_data, tuple) and len(rule_data) == 2 and isinstance(rule_data[0], dict) and 'error' in rule_data[0]:
            return rule_data
            
        # Add detection data
        detection_data = get_rule_detection_data(rule_id)
        if isinstance(detection_data, tuple) and len(detection_data) == 2 and isinstance(detection_data[0], dict) and 'error' in detection_data[0]:
            return detection_data
            
        rule_data['detection'] = detection_data['detection']
        rule_data['detection_metrics'] = detection_data['detection_metrics']
        
        # Calculate performance impact
        performance_data = estimate_rule_performance(rule_data)
        
        # Get deployment considerations
        deployment_considerations = get_deployment_considerations(rule_data)
        
        result = {
            'estimated_performance': performance_data,
            'deployment_considerations': deployment_considerations
        }
        
        # Cache the data
        if rule_id not in _rule_cache:
            _rule_cache[rule_id] = {}
        _rule_cache[rule_id]['performance'] = result
        
        return result
        
    except Exception as e:
        log_debug(f"Error getting performance data: {str(e)}")
        log_debug(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

def get_rule_related_data(rule_id):
    """Get dependencies and similar rules data"""
    try:
        # Check cache first
        if rule_id in _rule_cache and 'related' in _rule_cache[rule_id]:
            return _rule_cache[rule_id]['related']
            
        # Get basic rule data first
        rule_data = get_rule_basic_data(rule_id)
        if isinstance(rule_data, tuple) and len(rule_data) == 2 and isinstance(rule_data[0], dict) and 'error' in rule_data[0]:
            return rule_data
            
        # Add mitre data
        mitre_data = get_rule_mitre_data(rule_id)
        if isinstance(mitre_data, tuple) and len(mitre_data) == 2 and isinstance(mitre_data[0], dict) and 'error' in mitre_data[0]:
            return mitre_data
            
        rule_data['mitre_attack'] = mitre_data['mitre_attack']
        
        # Find dependencies
        dependency_data = find_rule_dependencies(rule_data)
        
        # Find similar rules
        similar_rules = find_similar_rules(rule_data)
        
        result = {
            'dependencies': dependency_data,
            'similar_rules': similar_rules
        }
        
        # Cache the data
        if rule_id not in _rule_cache:
            _rule_cache[rule_id] = {}
        _rule_cache[rule_id]['related'] = result
        
        return result
        
    except Exception as e:
        log_debug(f"Error getting related rule data: {str(e)}")
        log_debug(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

def get_rule_complete_data(rule_id):
    """Get all rule data (for caching)"""
    try:
        # Get all components
        basic_data = get_rule_basic_data(rule_id)
        if isinstance(basic_data, tuple) and len(basic_data) == 2 and isinstance(basic_data[0], dict) and 'error' in basic_data[0]:
            return basic_data
            
        mitre_data = get_rule_mitre_data(rule_id)
        if isinstance(mitre_data, tuple) and len(mitre_data) == 2 and isinstance(mitre_data[0], dict) and 'error' in mitre_data[0]:
            return mitre_data
            
        detection_data = get_rule_detection_data(rule_id)
        if isinstance(detection_data, tuple) and len(detection_data) == 2 and isinstance(detection_data[0], dict) and 'error' in detection_data[0]:
            return detection_data
            
        performance_data = get_rule_performance_data(rule_id)
        if isinstance(performance_data, tuple) and len(performance_data) == 2 and isinstance(performance_data[0], dict) and 'error' in performance_data[0]:
            return performance_data
            
        related_data = get_rule_related_data(rule_id)
        if isinstance(related_data, tuple) and len(related_data) == 2 and isinstance(related_data[0], dict) and 'error' in related_data[0]:
            return related_data
            
        # Combine all data
        complete_data = {**basic_data}
        complete_data['mitre_attack'] = mitre_data['mitre_attack']
        complete_data['detection'] = detection_data['detection']
        complete_data['detection_explanation'] = detection_data['detection_explanation']
        complete_data['estimated_performance'] = performance_data['estimated_performance']
        complete_data['deployment_considerations'] = performance_data['deployment_considerations']
        complete_data['dependencies'] = related_data['dependencies']['dependencies']
        complete_data['dependency_summary'] = related_data['dependencies']['summary']
        complete_data['similar_rules'] = related_data['similar_rules']
        
        # Cache the complete data
        if rule_id not in _rule_cache:
            _rule_cache[rule_id] = {}
        _rule_cache[rule_id]['complete'] = complete_data
        
        return complete_data
        
    except Exception as e:
        log_debug(f"Error getting complete rule data: {str(e)}")
        log_debug(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

# API routes
@api_bp.route('/rule/<rule_id>/basic', methods=['GET'])
def api_rule_basic(rule_id):
    """API endpoint for basic rule data"""
    result = get_rule_basic_data(rule_id)
    if isinstance(result, tuple):
        return result
    return jsonify(result)

@api_bp.route('/rule/<rule_id>/mitre', methods=['GET'])
def api_rule_mitre(rule_id):
    """API endpoint for MITRE ATT&CK data"""
    result = get_rule_mitre_data(rule_id)
    if isinstance(result, tuple):
        return result
    return jsonify(result)

@api_bp.route('/rule/<rule_id>/detection', methods=['GET'])
def api_rule_detection(rule_id):
    """API endpoint for detection logic"""
    result = get_rule_detection_data(rule_id)
    if isinstance(result, tuple):
        return result
    return jsonify(result)

@api_bp.route('/rule/<rule_id>/performance', methods=['GET'])
def api_rule_performance(rule_id):
    """API endpoint for performance impact"""
    result = get_rule_performance_data(rule_id)
    if isinstance(result, tuple):
        return result
    return jsonify(result)

@api_bp.route('/rule/<rule_id>/related', methods=['GET'])
def api_rule_related(rule_id):
    """API endpoint for dependencies and similar rules"""
    result = get_rule_related_data(rule_id)
    if isinstance(result, tuple):
        return result
    return jsonify(result)

@api_bp.route('/rule/<rule_id>/complete', methods=['GET'])
def api_rule_complete(rule_id):
    """API endpoint for all rule data (for caching)"""
    result = get_rule_complete_data(rule_id)
    if isinstance(result, tuple):
        return result
    return jsonify(result)

@api_bp.route('/cache/clear', methods=['POST'])
def api_clear_cache():
    """Clear the rule cache"""
    global _rule_cache
    _rule_cache = {}
    return jsonify({'status': 'success', 'message': 'Cache cleared'})
