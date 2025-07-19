def find_similar_rules(rule_data):
    """Find similar rules based on MITRE ATT&CK mappings and techniques"""
    similar_rules = []
    
    # Extract MITRE ATT&CK techniques from this rule
    mitre_techniques = rule_data.get('mitre_attack', [])
    
    # If no techniques, look at tags
    if not mitre_techniques:
        for tag in rule_data.get('tags', []):
            if tag.startswith('attack.t'):
                technique = tag.replace('attack.t', 'T').upper()
                if technique not in mitre_techniques:
                    mitre_techniques.append(technique)
    
    # If still no techniques, can't find similar rules based on MITRE ATT&CK
    if not mitre_techniques:
        # Return some generic similar rules
        return [
            {
                'id': 'windows_process_creation_suspicious_powershell',
                'title': 'Suspicious PowerShell Execution',
                'description': 'Detects suspicious PowerShell execution patterns',
                'similarity_reason': 'Common detection pattern',
                'similarity_score': 60,
                'level': 'medium',
                'url': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_powershell.yml'
            },
            {
                'id': 'windows_process_creation_suspicious_execution_path',
                'title': 'Execution from Suspicious Path',
                'description': 'Detects process execution from suspicious paths',
                'similarity_reason': 'Common detection pattern',
                'similarity_score': 55,
                'level': 'medium',
                'url': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_execution_path.yml'
            }
        ]
    
    # Create a list of well-known rules for similar techniques
    technique_to_rules = {
        'T1059': [
            {
                'id': 'powershell_suspicious_commands',
                'title': 'Suspicious PowerShell Commands',
                'description': 'Detects suspicious PowerShell command patterns that could indicate malicious activity',
                'similarity_reason': 'Command and Scripting Interpreter (T1059) technique',
                'similarity_score': 85,
                'level': 'high',
                'url': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_suspicious_parameter_variation.yml'
            },
            {
                'id': 'suspicious_command_line_pattern',
                'title': 'Suspicious Command Line Pattern',
                'description': 'Detects suspicious command line patterns that may indicate malicious activity',
                'similarity_reason': 'Command and Scripting Interpreter (T1059) technique',
                'similarity_score': 80,
                'level': 'medium',
                'url': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_command_pattern.yml'
            }
        ],
        'T1055': [
            {
                'id': 'process_injection_patterns',
                'title': 'Process Injection Patterns',
                'description': 'Detects patterns of process injection used by malware and attackers',
                'similarity_reason': 'Process Injection (T1055) technique',
                'similarity_score': 90,
                'level': 'high',
                'url': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_process_injection_pattern.yml'
            }
        ],
        'T1003': [
            {
                'id': 'credential_dumping_tools',
                'title': 'Credential Dumping Tools Detection',
                'description': 'Detects the use of credential dumping tools like Mimikatz',
                'similarity_reason': 'OS Credential Dumping (T1003) technique',
                'similarity_score': 85,
                'level': 'critical',
                'url': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_mimikatz_detection.yml'
            }
        ],
        'T1027': [
            {
                'id': 'obfuscated_commands',
                'title': 'Obfuscated Command Detection',
                'description': 'Detects obfuscated commands and scripts often used to evade detection',
                'similarity_reason': 'Obfuscated Files or Information (T1027) technique',
                'similarity_score': 80,
                'level': 'medium',
                'url': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_base64_encoded_cmd.yml'
            }
        ],
        'T1105': [
            {
                'id': 'remote_file_download',
                'title': 'Remote File Download',
                'description': 'Detects download of files from remote sources using various utilities',
                'similarity_reason': 'Ingress Tool Transfer (T1105) technique',
                'similarity_score': 75,
                'level': 'medium',
                'url': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_file_download.yml'
            }
        ],
        'T1218': [
            {
                'id': 'proxy_execution_via_lolbins',
                'title': 'Proxy Execution via LOLBINS',
                'description': 'Detects the use of built-in Windows utilities to proxy execution of code',
                'similarity_reason': 'System Binary Proxy Execution (T1218) technique',
                'similarity_score': 80,
                'level': 'high',
                'url': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_lolbin_execution.yml'
            }
        ]
    }
    
    # Add similar rules based on MITRE ATT&CK techniques
    for technique in mitre_techniques:
        # Extract base technique (without sub-technique)
        base_technique = technique.split('.')[0]
        
        if base_technique in technique_to_rules:
            similar_rules.extend(technique_to_rules[base_technique])
    
    # Add similar rules based on logsource (if available)
    logsource = rule_data.get('logsource', {})
    if logsource:
        product = logsource.get('product', '')
        service = logsource.get('service', '')
        category = logsource.get('category', '')
        
        if product == 'windows' and category == 'process_creation':
            # Add process creation rules if not already added
            if not any(rule['id'] == 'windows_process_creation_suspicious' for rule in similar_rules):
                similar_rules.append({
                    'id': 'windows_process_creation_suspicious',
                    'title': 'Suspicious Process Creation',
                    'description': 'Detects suspicious process creation patterns on Windows',
                    'similarity_reason': 'Similar log source (Windows process creation)',
                    'similarity_score': 65,
                    'level': 'medium',
                    'url': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_execution_path.yml'
                })
        
        if service == 'sysmon':
            # Add sysmon rules if not already added
            if not any(rule['id'] == 'sysmon_suspicious_activity' for rule in similar_rules):
                similar_rules.append({
                    'id': 'sysmon_suspicious_activity',
                    'title': 'Suspicious Activity Detected by Sysmon',
                    'description': 'Detects suspicious activity captured by Sysmon',
                    'similarity_reason': 'Similar log source (Sysmon)',
                    'similarity_score': 60,
                    'level': 'medium',
                    'url': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/sysmon/sysmon_suspicious_remote_thread.yml'
                })
    
    # Deduplicate and limit to top 5 most similar rules
    unique_rules = {}
    for rule in similar_rules:
        if rule['id'] not in unique_rules or rule['similarity_score'] > unique_rules[rule['id']]['similarity_score']:
            unique_rules[rule['id']] = rule
    
    # Sort by similarity score (descending) and limit to top 5
    top_similar_rules = sorted(
        list(unique_rules.values()),
        key=lambda x: x['similarity_score'],
        reverse=True
    )[:5]
    
    return top_similar_rules
