// Initialize Mermaid with theme support
document.addEventListener('DOMContentLoaded', function() {
  // Get current theme
  const scheme = document.querySelector('[data-md-color-scheme]');
  const isDark = scheme ? scheme.getAttribute('data-md-color-scheme') === 'slate' : false;
  
  // Configure Mermaid
  mermaid.initialize({
    startOnLoad: true,
    theme: isDark ? 'dark' : 'default',
    themeVariables: {
      primaryColor: '#9c27b0',
      primaryTextColor: isDark ? '#ffffff' : '#000000',
      primaryBorderColor: '#673ab7',
      lineColor: isDark ? '#ffffff' : '#333333',
      sectionBkgColor: isDark ? '#1a1a1a' : '#f5f5f5',
      altSectionBkgColor: isDark ? '#2a2a2a' : '#ffffff',
      gridColor: isDark ? '#444444' : '#cccccc'
    }
  });
  
  // Re-render on theme change with better error handling
  const observer = new MutationObserver(() => {
    const newScheme = document.querySelector('[data-md-color-scheme]');
    const newIsDark = newScheme ? newScheme.getAttribute('data-md-color-scheme') === 'slate' : false;
    
    if (newIsDark !== isDark) {
      try {
        mermaid.initialize({
          theme: newIsDark ? 'dark' : 'default',
          themeVariables: {
            primaryColor: '#9c27b0',
            primaryTextColor: newIsDark ? '#ffffff' : '#000000',
            primaryBorderColor: '#673ab7'
          }
        });
        
        // Reload page to apply new theme to diagrams
        setTimeout(() => location.reload(), 100);
      } catch (error) {
        console.log('Mermaid theme update failed:', error);
      }
    }
  });
  
  observer.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['data-md-color-scheme']
  });
});
