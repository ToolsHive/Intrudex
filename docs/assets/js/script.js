// Back to top functionality
document.addEventListener('DOMContentLoaded', function() {
  // Create back to top button
  const backToTopButton = document.createElement('button');
  backToTopButton.className = 'back-to-top';
  backToTopButton.innerHTML = '↑';
  backToTopButton.title = 'Back to top';
  document.body.appendChild(backToTopButton);

  // Show/hide button based on scroll position
  window.addEventListener('scroll', function() {
    if (window.pageYOffset > 300) {
      backToTopButton.classList.add('show');
    } else {
      backToTopButton.classList.remove('show');
    }
  });

  // Smooth scroll to top when clicked with custom animation
  backToTopButton.addEventListener('click', function() {
    let isScrollingToTop = true;
    
    const scrollToTop = () => {
      const currentPosition = document.documentElement.scrollTop || document.body.scrollTop;
      if (currentPosition > 0 && isScrollingToTop) {
        window.requestAnimationFrame(scrollToTop);
        window.scrollTo(0, currentPosition - currentPosition / 8);
      } else {
        isScrollingToTop = false;
      }
    };
    scrollToTop();
    
    // Stop animation if user manually scrolls during animation
    const stopAnimation = () => {
      isScrollingToTop = false;
      window.removeEventListener('wheel', stopAnimation);
      window.removeEventListener('touchmove', stopAnimation);
    };
    
    window.addEventListener('wheel', stopAnimation);
    window.addEventListener('touchmove', stopAnimation);
  });

  // Enhanced image loading with fade-in effect
  const images = document.querySelectorAll('img');
  images.forEach(img => {
    img.style.opacity = '0';
    img.style.transition = 'opacity 0.3s ease';
    
    img.addEventListener('load', function() {
      this.style.opacity = '1';
    });
    
    // If image is already loaded
    if (img.complete) {
      img.style.opacity = '1';
    }
  });

  // Simplified copy functionality (no custom toasts)
  const addCopyFunctionality = () => {
    // Only enhance Material's built-in copy buttons if needed
    const observer = new MutationObserver(() => {
      const materialCopyBtns = document.querySelectorAll('.md-clipboard');
      materialCopyBtns.forEach(btn => {
        if (!btn.dataset.enhanced) {
          btn.dataset.enhanced = 'true';
          // Material already shows its own feedback, no need for custom toast
        }
      });
    });
    
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  };

  // Smooth scrolling for anchor links
  const anchorLinks = document.querySelectorAll('a[href^="#"]');
  anchorLinks.forEach(link => {
    link.addEventListener('click', function(e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }
    });
  });

  // Reading progress indicator
  const progressBar = document.createElement('div');
  progressBar.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 0%;
    height: 3px;
    background: var(--md-accent-fg-color);
    z-index: 1001;
    transition: width 0.1s ease;
  `;
  document.body.appendChild(progressBar);

  window.addEventListener('scroll', function() {
    const winScroll = document.body.scrollTop || document.documentElement.scrollTop;
    const height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
    const scrolled = (winScroll / height) * 100;
    progressBar.style.width = scrolled + '%';
  });
  
  // Dark/Light mode preference saver
  const saveThemePreference = () => {
    const observer = new MutationObserver(() => {
      const scheme = document.querySelector('[data-md-color-scheme]');
      if (scheme) {
        localStorage.setItem('theme-preference', scheme.getAttribute('data-md-color-scheme'));
      }
    });
    
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-md-color-scheme']
    });
  };

  // Keyboard shortcuts
  const addKeyboardShortcuts = () => {
    document.addEventListener('keydown', function(e) {
      // Ctrl/Cmd + K for search
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const searchInput = document.querySelector('input[type="search"]') || 
                           document.querySelector('.md-search__input');
        if (searchInput) {
          searchInput.focus();
          searchInput.select();
        }
      }
    });
  };

  // Enhanced Table of contents auto-highlighting
  const addTocHighlighting = () => {
    const tocLinks = document.querySelectorAll('.md-nav--secondary .md-nav__link');
    const headings = Array.from(document.querySelectorAll('h1[id], h2[id], h3[id], h4[id], h5[id], h6[id]'));
    
    if (tocLinks.length && headings.length) {
      const observer = new IntersectionObserver((entries) => {
        let visibleHeadings = [];
        
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            visibleHeadings.push(entry.target);
          }
        });
        
        if (visibleHeadings.length > 0) {
          // Sort by position and take the topmost
          visibleHeadings.sort((a, b) => a.getBoundingClientRect().top - b.getBoundingClientRect().top);
          const activeHeading = visibleHeadings[0];
          
          // Remove active class from all links
          tocLinks.forEach(link => {
            link.classList.remove('md-nav__link--active');
            link.style.color = '';
            link.style.fontWeight = '';
          });
          
          // Add active class to current heading link
          const activeLink = document.querySelector(`.md-nav--secondary a[href="#${activeHeading.id}"]`);
          if (activeLink) {
            activeLink.classList.add('md-nav__link--active');
            activeLink.style.color = 'var(--md-accent-fg-color)';
            activeLink.style.fontWeight = '600';
          }
        }
      }, { 
        threshold: 0.3,
        rootMargin: '-20% 0px -60% 0px'
      });
      
      headings.forEach(heading => observer.observe(heading));
    }
  };

  // Initialize features
  saveThemePreference();
  addKeyboardShortcuts();
  addTocHighlighting();
  addCopyFunctionality();
});