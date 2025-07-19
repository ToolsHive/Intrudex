"""
Rule quality assessment utilities for Sigma rules
"""

def calculate_comprehensive_quality_score(rule_data):
    """Calculate a comprehensive quality score for a Sigma rule based on multiple factors
    
    Args:
        rule_data (dict): The Sigma rule data dictionary
        
    Returns:
        tuple: (score, factors) where score is an integer 0-100 and factors is a dict of subscores
    """
    score = 60  # Start with a baseline score
    
    # Initialize quality factors dictionary
    quality_factors = {
        'completeness': 0,
        'mitre_mapping': 0,
        'documentation': 0,
        'detection_logic': 0,
        'false_positive_handling': 0
    }
    
    # Has proper title and description (basic documentation)
    if rule_data.get('title') and rule_data.get('description'):
        score += 10
        quality_factors['documentation'] += 60
    
    # Has MITRE ATT&CK mappings
    mitre_mappings = rule_data.get('tags', [])
    attack_tags = [tag for tag in mitre_mappings if 'attack.' in tag]
    if attack_tags:
        mapping_score = min(len(attack_tags) * 5, 15)  # Up to 15 points for MITRE mappings
        score += mapping_score
        quality_factors['mitre_mapping'] = min(40 + mapping_score * 4, 100)
    
    # Has proper condition logic
    if 'detection' in rule_data and isinstance(rule_data['detection'], dict):
        if 'condition' in rule_data['detection']:
            condition = rule_data['detection']['condition']
            if condition and isinstance(condition, str):
                # More points for complex conditions (containing AND, OR, NOT)
                if any(op in condition.upper() for op in ['AND', 'OR', 'NOT']):
                    score += 15
                    quality_factors['detection_logic'] += 80
                else:
                    score += 10
                    quality_factors['detection_logic'] += 60
    
    # Has proper author information
    if rule_data.get('author'):
        score += 5
        quality_factors['completeness'] += 20
    
    # Has references
    references = rule_data.get('references', [])
    if references:
        ref_score = min(len(references) * 2, 10)
        score += ref_score
        quality_factors['documentation'] += min(ref_score * 4, 40)
    
    # Has tags (beyond MITRE ATT&CK)
    tags = [tag for tag in rule_data.get('tags', []) if 'attack.' not in tag]
    if tags:
        score += min(len(tags) * 2, 10)
        quality_factors['completeness'] += min(len(tags) * 5, 20)
    
    # Has false positives documentation
    if rule_data.get('falsepositives'):
        fp_items = rule_data['falsepositives']
        if isinstance(fp_items, list) and len(fp_items) > 0:
            fp_score = min(len(fp_items) * 3, 10)
            score += fp_score
            quality_factors['false_positive_handling'] = min(50 + fp_score * 5, 100)
    
    # Has status information
    if rule_data.get('status'):
        score += 5
        quality_factors['completeness'] += 10
    
    # Has date information
    if rule_data.get('date') or rule_data.get('modified'):
        score += 5
        quality_factors['completeness'] += 10
    
    # Deductions for potential issues
    
    # Very simple detection logic
    if 'detection' in rule_data and isinstance(rule_data['detection'], dict):
        detection_keys = [k for k in rule_data['detection'].keys() if k != 'condition']
        if len(detection_keys) <= 1:
            score -= 15
            quality_factors['detection_logic'] = max(quality_factors['detection_logic'] - 30, 0)
    
    # Missing severity level
    if not rule_data.get('level'):
        score -= 10
        quality_factors['completeness'] = max(quality_factors['completeness'] - 20, 0)
    
    # Normalize score to 0-100 range
    score = max(0, min(score, 100))
    
    # Fill in remaining quality factors based on overall score
    if 'completeness' not in quality_factors or quality_factors['completeness'] == 0:
        quality_factors['completeness'] = min(100, score + 10)  # Slightly higher than overall score
    
    if 'mitre_mapping' not in quality_factors or quality_factors['mitre_mapping'] == 0:
        quality_factors['mitre_mapping'] = 100 if attack_tags else 40
    
    if 'documentation' not in quality_factors or quality_factors['documentation'] == 0:
        quality_factors['documentation'] = 100 if (rule_data.get('description') and references) else 50
    
    if 'detection_logic' not in quality_factors or quality_factors['detection_logic'] == 0:
        quality_factors['detection_logic'] = 90 if ('detection' in rule_data and isinstance(rule_data['detection'], dict)) else 30
    
    if 'false_positive_handling' not in quality_factors or quality_factors['false_positive_handling'] == 0:
        quality_factors['false_positive_handling'] = 70 if rule_data.get('falsepositives') else 30
    
    return score, quality_factors
