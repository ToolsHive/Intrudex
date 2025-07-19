/**
 * Sigma Rule Details Progressive Loading & Caching
 * 
 * This script handles:
 * 1. Progressive loading of rule details with skeleton screens
 * 2. Client-side caching of rule data for faster loads
 * 3. Progress tracking for data loading
 */

// Cache object for storing rule data
const ruleCache = {
    // Try to load any existing cache from localStorage
    data: (() => {
        try {
            const cached = localStorage.getItem('intrudex_rule_cache');
            return cached ? JSON.parse(cached) : {};
        } catch (e) {
            console.error("Cache loading error:", e);
            return {};
        }
    })(),
    
    // Store a rule in the cache
    storeRule: function(ruleId, ruleData) {
        this.data[ruleId] = {
            data: ruleData,
            timestamp: Date.now()
        };
        
        // Save to localStorage
        try {
            localStorage.setItem('intrudex_rule_cache', JSON.stringify(this.data));
        } catch (e) {
            console.error("Cache storing error:", e);
        }
    },
    
    // Get a rule from the cache if it exists and isn't expired
    getRule: function(ruleId) {
        const cached = this.data[ruleId];
        
        if (!cached) return null;
        
        // Check if cache is older than 1 hour (3600000 ms)
        if (Date.now() - cached.timestamp > 3600000) {
            delete this.data[ruleId];
            return null;
        }
        
        return cached.data;
    }
};

// Track loading progress
let loadingProgress = 0;
const progressBar = document.getElementById('loading-progress');
const progressPercentage = document.getElementById('progress-percentage');

// Update the progress bar
function updateProgress(value) {
    loadingProgress = value;
    
    if (progressBar) {
        progressBar.style.width = `${value}%`;
    }
    
    if (progressPercentage) {
        progressPercentage.textContent = `${Math.round(value)}%`;
    }
}

// Show and hide skeleton screens
function toggleSkeletonScreen(sectionId, show = true) {
    const section = document.getElementById(sectionId);
    if (!section) return;
    
    const skeleton = document.getElementById(`${sectionId}-skeleton`);
    const content = document.getElementById(`${sectionId}-content`);
    
    if (skeleton && content) {
        skeleton.classList.toggle('hidden', !show);
        content.classList.toggle('hidden', show);
    }
}

// Show all skeleton screens initially
function showAllSkeletons() {
    const sections = [
        'rule-basic-info',
        'rule-mitre',
        'rule-detection',
        'rule-performance',
        'rule-dependencies',
        'rule-similar'
    ];
    
    sections.forEach(section => {
        toggleSkeletonScreen(section, true);
    });
    
    document.getElementById('loading-container').classList.remove('hidden');
}

// Hide all skeleton screens when loading completes
function hideAllSkeletons() {
    const sections = [
        'rule-basic-info',
        'rule-mitre',
        'rule-detection',
        'rule-performance',
        'rule-dependencies',
        'rule-similar'
    ];
    
    sections.forEach(section => {
        toggleSkeletonScreen(section, false);
    });
    
    document.getElementById('loading-container').classList.add('hidden');
}

// Load rule data progressively
function loadRuleData(ruleId) {
    // Show skeleton screens
    showAllSkeletons();
    updateProgress(5);
    
    // Check if we have cached data
    const cachedRule = ruleCache.getRule(ruleId);
    if (cachedRule) {
        console.log("Using cached rule data");
        
        // Still use progressive loading but much faster
        setTimeout(() => { 
            updateProgress(30);
            updateRuleBasicInfo(cachedRule);
            toggleSkeletonScreen('rule-basic-info', false);
        }, 100);
        
        setTimeout(() => {
            updateProgress(50);
            updateRuleMitreInfo(cachedRule);
            toggleSkeletonScreen('rule-mitre', false);
        }, 200);
        
        setTimeout(() => {
            updateProgress(70);
            updateRuleDetection(cachedRule);
            toggleSkeletonScreen('rule-detection', false);
        }, 300);
        
        setTimeout(() => {
            updateProgress(90);
            updateRulePerformance(cachedRule);
            updateRuleDependencies(cachedRule);
            toggleSkeletonScreen('rule-performance', false);
            toggleSkeletonScreen('rule-dependencies', false);
        }, 400);
        
        setTimeout(() => {
            updateProgress(100);
            updateRuleSimilar(cachedRule);
            toggleSkeletonScreen('rule-similar', false);
            document.getElementById('loading-container').classList.add('hidden');
        }, 500);
        
        return;
    }
    
    // Fetch rule data in chunks
    fetch(`/sigmarules/api/rule/${ruleId}/basic`)
        .then(response => response.json())
        .then(data => {
            updateProgress(30);
            updateRuleBasicInfo(data);
            toggleSkeletonScreen('rule-basic-info', false);
            
            return fetch(`/sigmarules/api/rule/${ruleId}/mitre`);
        })
        .then(response => response.json())
        .then(data => {
            updateProgress(50);
            updateRuleMitreInfo(data);
            toggleSkeletonScreen('rule-mitre', false);
            
            return fetch(`/sigmarules/api/rule/${ruleId}/detection`);
        })
        .then(response => response.json())
        .then(data => {
            updateProgress(70);
            updateRuleDetection(data);
            toggleSkeletonScreen('rule-detection', false);
            
            return fetch(`/sigmarules/api/rule/${ruleId}/performance`);
        })
        .then(response => response.json())
        .then(data => {
            updateProgress(85);
            updateRulePerformance(data);
            toggleSkeletonScreen('rule-performance', false);
            
            return fetch(`/sigmarules/api/rule/${ruleId}/related`);
        })
        .then(response => response.json())
        .then(data => {
            updateProgress(100);
            updateRuleDependencies(data);
            updateRuleSimilar(data);
            toggleSkeletonScreen('rule-dependencies', false);
            toggleSkeletonScreen('rule-similar', false);
            
            // Cache the complete rule data
            fetch(`/sigmarules/api/rule/${ruleId}/complete`)
                .then(response => response.json())
                .then(completeData => {
                    ruleCache.storeRule(ruleId, completeData);
                });
                
            document.getElementById('loading-container').classList.add('hidden');
        })
        .catch(error => {
            console.error("Error loading rule data:", error);
            document.getElementById('loading-container').classList.add('hidden');
            document.getElementById('error-container').classList.remove('hidden');
        });
}

// Update DOM functions for each section
function updateRuleBasicInfo(data) {
    // Update the basic rule information
    if (!data) return;
    
    document.getElementById('rule-title').textContent = data.title || 'Unknown Rule';
    document.getElementById('rule-description').textContent = data.description || 'No description available';
    
    // Update quality and severity badges
    const qualityBadge = document.getElementById('quality-badge');
    if (qualityBadge && data.quality_level) {
        qualityBadge.textContent = `${data.quality_level.charAt(0).toUpperCase() + data.quality_level.slice(1)} Quality`;
    }
    
    const severityBadge = document.getElementById('severity-badge');
    if (severityBadge && data.level) {
        severityBadge.textContent = `${data.level.charAt(0).toUpperCase() + data.level.slice(1)} Severity`;
    }
    
    // Update metadata fields
    if (data.author) document.getElementById('rule-author').textContent = data.author;
    if (data.date) document.getElementById('rule-date').textContent = data.date;
    if (data.modified) document.getElementById('rule-modified').textContent = data.modified;
    if (data.status) document.getElementById('rule-status').textContent = data.status;
}

function updateRuleMitreInfo(data) {
    // Update MITRE ATT&CK information
    if (!data || !data.mitre_attack) return;
    
    const mitreContainer = document.getElementById('mitre-techniques-container');
    if (!mitreContainer) return;
    
    mitreContainer.innerHTML = '';
    
    data.mitre_attack.forEach(technique => {
        if (typeof technique === 'string') {
            // Simple case with just technique IDs
            const techniqueEl = document.createElement('div');
            techniqueEl.className = 'bg-gray-800/50 border border-gray-700 rounded-lg p-4 hover:bg-gray-700/50 transition-all';
            techniqueEl.innerHTML = `
                <div class="font-semibold text-blue-300">${technique}</div>
                <div class="text-gray-400 text-sm mt-1">MITRE ATT&CK Technique</div>
            `;
            mitreContainer.appendChild(techniqueEl);
        } else if (typeof technique === 'object') {
            // Enhanced case with full technique objects
            const techniqueEl = document.createElement('div');
            techniqueEl.className = 'bg-gray-800/50 border border-gray-700 rounded-lg p-4 hover:bg-gray-700/50 transition-all';
            techniqueEl.innerHTML = `
                <div class="font-semibold text-blue-300">${technique.technique_id || ''}: ${technique.name || ''}</div>
                <div class="text-gray-300 text-sm mt-1">${technique.description || ''}</div>
                <div class="mt-2 flex flex-wrap gap-2">
                    ${technique.tactics ? technique.tactics.map(tactic => 
                        `<span class="px-2 py-1 bg-blue-900/30 text-blue-300 rounded text-xs">${tactic}</span>`
                    ).join('') : ''}
                </div>
            `;
            mitreContainer.appendChild(techniqueEl);
        }
    });
}

function updateRuleDetection(data) {
    // Update detection logic
    if (!data || !data.detection) return;
    
    const detectionExplanation = document.getElementById('detection-explanation');
    if (detectionExplanation && data.detection_explanation) {
        detectionExplanation.textContent = data.detection_explanation;
    }
    
    // Update detection code sample
    const detectionCode = document.getElementById('detection-code');
    if (detectionCode && data.detection) {
        let detectionText = '';
        
        try {
            if (typeof data.detection === 'string') {
                detectionText = data.detection;
            } else {
                detectionText = JSON.stringify(data.detection, null, 2);
            }
        } catch (e) {
            detectionText = 'Error parsing detection logic';
        }
        
        detectionCode.textContent = detectionText;
        
        // Initialize syntax highlighting if available
        if (window.hljs) {
            window.hljs.highlightElement(detectionCode);
        }
    }
}

function updateRulePerformance(data) {
    // Update performance impact
    if (!data || !data.estimated_performance) return;
    
    const performance = data.estimated_performance;
    
    // Update impact level
    const impactLevel = document.getElementById('impact-level');
    if (impactLevel) {
        impactLevel.textContent = performance.impact_level || 'Unknown';
        
        // Update color based on impact
        if (performance.impact_level === 'Low') {
            impactLevel.className = 'text-green-400 font-bold';
        } else if (performance.impact_level === 'Medium') {
            impactLevel.className = 'text-yellow-400 font-bold';
        } else if (performance.impact_level === 'High') {
            impactLevel.className = 'text-red-400 font-bold';
        }
    }
    
    // Update impact description
    const impactDescription = document.getElementById('impact-description');
    if (impactDescription) {
        impactDescription.textContent = performance.impact_description || '';
    }
    
    // Update factors
    const factorsContainer = document.getElementById('performance-factors');
    if (factorsContainer && performance.factors) {
        factorsContainer.innerHTML = '';
        
        performance.factors.forEach(factor => {
            const factorEl = document.createElement('li');
            factorEl.className = 'text-gray-300';
            factorEl.textContent = factor;
            factorsContainer.appendChild(factorEl);
        });
    }
    
    // Update recommendations
    const recommendationsContainer = document.getElementById('performance-recommendations');
    if (recommendationsContainer && performance.recommendations) {
        recommendationsContainer.innerHTML = '';
        
        performance.recommendations.forEach(recommendation => {
            const recEl = document.createElement('li');
            recEl.className = 'text-gray-300';
            recEl.textContent = recommendation;
            recommendationsContainer.appendChild(recEl);
        });
    }
}

function updateRuleDependencies(data) {
    // Update dependencies
    if (!data || !data.dependencies) return;
    
    const dependenciesContainer = document.getElementById('dependencies-container');
    if (!dependenciesContainer) return;
    
    dependenciesContainer.innerHTML = '';
    
    // Add each dependency
    data.dependencies.dependencies.forEach(dep => {
        const depEl = document.createElement('div');
        depEl.className = 'bg-gray-800/50 border border-gray-700 rounded-lg p-4';
        
        // Add criticality indicator
        let criticalityClass = 'bg-gray-500';
        if (dep.criticality === 'critical') criticalityClass = 'bg-red-500';
        if (dep.criticality === 'high') criticalityClass = 'bg-orange-500';
        if (dep.criticality === 'medium') criticalityClass = 'bg-yellow-500';
        
        depEl.innerHTML = `
            <div class="flex items-center gap-3">
                <div class="w-3 h-3 ${criticalityClass} rounded-full"></div>
                <h3 class="font-semibold text-gray-200">${dep.name || dep.id || 'Unknown'}</h3>
            </div>
            <p class="text-gray-400 mt-2">${dep.description || ''}</p>
            ${dep.link ? `<a href="${dep.link}" target="_blank" class="text-blue-400 hover:underline text-sm mt-2 inline-block">Learn more</a>` : ''}
        `;
        
        dependenciesContainer.appendChild(depEl);
    });
    
    // Update summary
    const summary = data.dependencies.summary;
    if (summary) {
        const complexityEl = document.getElementById('dependency-complexity');
        if (complexityEl) {
            complexityEl.textContent = summary.deployment_complexity || 'Unknown';
            
            // Update color
            if (summary.deployment_complexity === 'Low') {
                complexityEl.className = 'text-green-400 font-bold';
            } else if (summary.deployment_complexity === 'Medium') {
                complexityEl.className = 'text-yellow-400 font-bold';
            } else if (summary.deployment_complexity === 'High') {
                complexityEl.className = 'text-red-400 font-bold';
            }
        }
        
        // Update counts
        if (summary.critical_count) document.getElementById('critical-count').textContent = summary.critical_count;
        if (summary.high_count) document.getElementById('high-count').textContent = summary.high_count;
        if (summary.medium_count) document.getElementById('medium-count').textContent = summary.medium_count;
        if (summary.low_count) document.getElementById('low-count').textContent = summary.low_count;
    }
}

function updateRuleSimilar(data) {
    // Update similar rules
    if (!data || !data.similar_rules) return;
    
    const similarContainer = document.getElementById('similar-rules-container');
    if (!similarContainer) return;
    
    similarContainer.innerHTML = '';
    
    // Add each similar rule
    data.similar_rules.forEach(rule => {
        const ruleEl = document.createElement('div');
        ruleEl.className = 'bg-gray-800/50 border border-gray-700 rounded-lg p-4';
        
        ruleEl.innerHTML = `
            <div class="flex items-center justify-between">
                <h3 class="font-semibold text-gray-200">${rule.title || 'Unknown Rule'}</h3>
                <span class="px-2 py-1 rounded-full text-xs ${rule.level === 'high' ? 'bg-red-500/30 text-red-300' : 
                    rule.level === 'medium' ? 'bg-yellow-500/30 text-yellow-300' : 'bg-blue-500/30 text-blue-300'}">
                    ${rule.level || 'unknown'}
                </span>
            </div>
            <p class="text-gray-400 text-sm mt-2">${rule.description || ''}</p>
            <div class="mt-3 flex items-center justify-between">
                <span class="text-gray-500 text-xs">Similarity: ${rule.similarity_score || 0}%</span>
                ${rule.url ? `<a href="${rule.url}" target="_blank" class="text-blue-400 hover:underline text-sm">View Rule</a>` : ''}
            </div>
        `;
        
        similarContainer.appendChild(ruleEl);
    });
    
    // If no similar rules
    if (data.similar_rules.length === 0) {
        similarContainer.innerHTML = '<p class="text-gray-400">No similar rules found</p>';
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    const ruleId = document.getElementById('rule-id')?.value;
    
    if (ruleId) {
        loadRuleData(ruleId);
    }
});
