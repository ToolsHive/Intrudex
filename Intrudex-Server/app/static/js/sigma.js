   let selectedFolderPath = '';
   let flatFolders = [];
   let flatFiles = [];
   let lastSearchQuery = "";

   // Helper: highlight all matches in a string using Fuse.js result indices
   function highlightMatch(text, indices) {
     if (!indices || !indices.length) return text;
     let result = '';
     let lastIndex = 0;
     indices.forEach(([start, end]) => {
       result += text.slice(lastIndex, start);
       result += `<span class="sigma-highlight">${text.slice(start, end + 1)}</span>`;
       lastIndex = end + 1;
     });
     result += text.slice(lastIndex);
     return result;
   }

   // Flatten folders for sidebar
   function flattenFolders(tree, parentPath = '') {
     let out = [];
     tree.forEach(entry => {
       const fullPath = parentPath ? parentPath + '/' + entry.name : entry.name;
       if (entry.type === 'folder') {
         out.push({
           ...entry,
           fullPath,
           isFolder: true,
           children: undefined
         });
         out = out.concat(flattenFolders(entry.children, fullPath));
       }
     });
     return out;
   }

   // Flatten files for search
   function flattenFiles(tree, parentPath = '') {
     let out = [];
     tree.forEach(entry => {
       const fullPath = parentPath ? parentPath + '/' + entry.name : entry.name;
       if (entry.type === 'folder') {
         out = out.concat(flattenFiles(entry.children, fullPath));
       } else {
         out.push({
           ...entry,
           fullPath,
           isFolder: false
         });
       }
     });
     return out;
   }

   // Render folder tree (sidebar)
   function renderFolderTree(tree, parentPath = '', openPaths = new Set(), highlight = '', folderMatches = {}, fuseQuery = '') {
     let html = '<ul class="pl-2">';
     tree.forEach((entry, idx) => {
       if (entry.type === 'folder') {
         const fullPath = parentPath ? parentPath + '/' + entry.name : entry.name;
         const isOpen = openPaths.has(fullPath);
         const isSelected = selectedFolderPath === fullPath;
         const highlightClass = highlight && fullPath.toLowerCase().includes(highlight.toLowerCase()) ? 'bg-yellow-400/20' : '';
         let folderLabel = entry.name;
         if (folderMatches && folderMatches[fullPath]) {
           folderLabel = highlightMatch(entry.name, folderMatches[fullPath]);
         }
         html += `
           <li>
             <div class="flex items-center cursor-pointer px-2 py-1 rounded-lg transition group ${highlightClass} ${isSelected ? 'bg-yellow-400/30 text-yellow-300 font-bold' : 'hover:bg-gray-800/80'}"
                  data-folder-path="${fullPath}"
                  onclick="selectFolder('${fullPath.replace(/'/g,"\\'")}')">
               <svg class="w-4 h-4 mr-2 transition-transform duration-200 ${isOpen ? 'rotate-90' : ''}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                 <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
               </svg>
               <svg class="w-5 h-5 mr-2 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
                 <path d="M2 6a2 2 0 012-2h12a2 2 0 012 2v10a2 2 0 01-2 2H4a2 2 0 01-2-2V6z"/>
               </svg>
               <span class="truncate">${folderLabel}</span>
             </div>
             <div class="ml-5 transition-all duration-300" style="display:${isOpen ? 'block' : 'none'}" data-folder-children="${fullPath}">
               ${renderFolderTree(entry.children, fullPath, openPaths, highlight, folderMatches, fuseQuery)}
             </div>
           </li>
         `;
       }
     });
     html += '</ul>';
     return html;
   }

   // Render file list for selected folder
   function renderFileList(tree, folderPath, fileMatches = {}, fuseQuery = '') {
     function findFolder(tree, pathParts) {
       if (!pathParts.length) return tree;
       const [head, ...rest] = pathParts;
       const node = tree.find(e => e.type === 'folder' && e.name === head);
       if (!node) return [];
       if (!rest.length) return node.children;
       return findFolder(node.children, rest);
     }
     const pathParts = folderPath ? folderPath.split('/') : [];
     const files = findFolder(window._sigmaTree, pathParts) || [];
     let html = '';
     if (files.length === 0) {
       html = `<div class="text-gray-400 italic">No files or subfolders in this folder.</div>`;
     } else {
       html += '<ul class="space-y-2">';
       files.forEach(entry => {
         if (entry.type === 'folder') {
           html += `
             <li class="flex items-center px-3 py-2 rounded-lg bg-gray-800/70 border border-gray-700 hover:bg-yellow-400/10 transition cursor-pointer"
                 onclick="selectFolder('${(folderPath ? folderPath + '/' : '') + entry.name}')">
               <svg class="w-5 h-5 mr-3 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
                 <path d="M2 6a2 2 0 012-2h12a2 2 0 012 2v10a2 2 0 01-2 2H4a2 2 0 01-2-2V6z"/>
               </svg>
               <span class="truncate font-semibold text-yellow-200">${entry.name}</span>
             </li>
           `;
         } else {
           let fileLabel = entry.name;
           if (fileMatches && fileMatches[entry.fullPath]) {
             fileLabel = highlightMatch(entry.name, fileMatches[entry.fullPath]);
           }
           html += `
             <li class="flex items-center px-3 py-2 rounded-lg bg-gray-900/80 border border-gray-700 hover:bg-blue-900/30 transition">
               <svg class="w-5 h-5 mr-3 text-green-400" fill="currentColor" viewBox="0 0 20 20">
                 <path d="M17 16V4a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2z"/>
               </svg>
               <a href="/sigma/view/${entry.path}" class="flex-1 text-blue-200 hover:text-yellow-300 font-mono truncate underline-offset-2 hover:underline">${fileLabel}</a>
             </li>
           `;
         }
       });
       html += '</ul>';
     }
     return html;
   }

   // Render breadcrumbs
   function renderBreadcrumbs(folderPath) {
     if (!folderPath) return '';
     const parts = folderPath.split('/');
     let html = '<nav class="flex items-center space-x-2">';
     let path = '';
     parts.forEach((part, idx) => {
       path += (idx === 0 ? '' : '/') + part;
       html += `<a href="javascript:void(0)" onclick="selectFolder('${path.replace(/'/g,"\\'")}')" class="text-yellow-300 hover:underline">${part}</a>`;
       if (idx < parts.length - 1) {
         html += '<span class="text-gray-500">/</span>';
       }
     });
     html += '</nav>';
     return html;
   }

   // Select folder and update file list
   function selectFolder(folderPath) {
     selectedFolderPath = folderPath;
     const openPaths = new Set();
     let path = '';
     folderPath.split('/').forEach(part => {
       path = path ? path + '/' + part : part;
       openPaths.add(path);
     });
     document.getElementById('sigma-tree-list').innerHTML = renderFolderTree(window._sigmaTree, '', openPaths, document.getElementById('sigma-search').value, {}, lastSearchQuery);
     document.getElementById('sigma-file-list').innerHTML = renderFileList(window._sigmaTree, folderPath, {}, lastSearchQuery);
     document.getElementById('sigma-breadcrumbs').innerHTML = renderBreadcrumbs(folderPath);
     attachSidebarDropdowns();
   }

   // Attach expand/collapse logic to sidebar
   function attachSidebarDropdowns() {
     document.querySelectorAll('#sigma-tree-list .folder-item > .folder-toggle').forEach(toggle => {
       toggle.onclick = function(e) {
         if (e.target.tagName === 'A') return;
         const folderDiv = toggle.parentElement;
         const folderPath = folderDiv.getAttribute('data-folder');
         const childrenDiv = folderDiv.nextElementSibling;
         const arrow = toggle.querySelector('svg');
         if (childrenDiv.style.display === 'block') {
           childrenDiv.style.display = 'none';
           arrow.classList.remove('rotate-90');
         } else {
           childrenDiv.style.display = 'block';
           arrow.classList.add('rotate-90');
         }
       };
     });
   }

   // Search logic for folders/files
   function searchSigmaTree(query) {
     lastSearchQuery = query;
     query = query.trim();
     if (!query) {
       document.getElementById('sigma-tree-list').innerHTML = renderFolderTree(window._sigmaTree, '', new Set(), '', {}, '');
       document.getElementById('sigma-file-list').innerHTML = renderFileList(window._sigmaTree, selectedFolderPath, {}, '');
       return;
     }
     const fuseOptions = {
       keys: ['name', 'fullPath'],
       threshold: 0.0,
       ignoreLocation: true,
       includeScore: true,
       minMatchCharLength: 1,
       includeMatches: true,
       useExtendedSearch: true
     };
     const fuseFolders = new Fuse(flatFolders, fuseOptions);
     const fuseFiles = new Fuse(flatFiles, fuseOptions);

     const searchObj = { $or: [{ name: `'${query}` }, { fullPath: `'${query}` }] };
     const folderResults = fuseFolders.search(searchObj);
     const fileResults = fuseFiles.search(searchObj);

     const folderMatches = {};
     folderResults.forEach(r => {
       if (r.matches && r.matches[0] && r.matches[0].key === 'name') {
         folderMatches[r.item.fullPath] = r.matches[0].indices;
       }
     });
     const fileMatches = {};
     fileResults.forEach(r => {
       if (r.matches && r.matches[0] && r.matches[0].key === 'name') {
         fileMatches[r.item.fullPath] = r.matches[0].indices;
       }
     });

     const openPaths = new Set();
     folderResults.concat(fileResults).forEach(r => {
       let path = r.item.fullPath;
       while (path) {
         openPaths.add(path);
         if (!path.includes('/')) break;
         path = path.substring(0, path.lastIndexOf('/'));
       }
     });

     document.getElementById('sigma-tree-list').innerHTML = renderFolderTree(window._sigmaTree, '', openPaths, query, folderMatches, query);

     let html = '';
     if (fileResults.length === 0) {
       html = `<div class="text-gray-400 italic">No files found for "<span class="text-yellow-300">${query}</span>".</div>`;
     } else {
       html += '<ul class="space-y-2">';
       flatFiles.forEach(entry => {
         if (fileMatches[entry.fullPath]) {
           let fileLabel = highlightMatch(entry.name, fileMatches[entry.fullPath]);
           html += `
             <li class="flex items-center px-3 py-2 rounded-lg bg-gray-900/80 border border-gray-700 hover:bg-blue-900/30 transition">
               <svg class="w-5 h-5 mr-3 text-green-400" fill="currentColor" viewBox="0 0 20 20">
                 <path d="M17 16V4a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2z"/>
               </svg>
               <a href="/sigma/view/${entry.path}" class="flex-1 text-blue-200 hover:text-yellow-300 font-mono truncate underline-offset-2 hover:underline">${fileLabel}</a>
               <span class="ml-2 text-xs text-gray-500">${entry.fullPath}</span>
             </li>
           `;
         }
       });
       html += '</ul>';
     }
     document.getElementById('sigma-file-list').innerHTML = html;
     document.getElementById('sigma-breadcrumbs').innerHTML = '';
     attachSidebarDropdowns();
   }

   document.addEventListener('DOMContentLoaded', function() {
     flatFolders = flattenFolders(window._sigmaTree);
     flatFiles = flattenFiles(window._sigmaTree);

     selectedFolderPath = '';
     document.getElementById('sigma-tree-list').innerHTML = renderFolderTree(window._sigmaTree, '', new Set(), '', {}, '');
     document.getElementById('sigma-file-list').innerHTML = renderFileList(window._sigmaTree, '', {}, '');
     document.getElementById('sigma-breadcrumbs').innerHTML = '';

     attachSidebarDropdowns();

     const searchInput = document.getElementById('sigma-search');
     searchInput.addEventListener('input', function() {
       searchSigmaTree(this.value);
     });
   });

   // --- Export Button Logic ---
   document.addEventListener('DOMContentLoaded', function() {
     const exportBtn = document.getElementById('export-folder-btn');
     function updateExportBtn() {
       if (selectedFolderPath) {
         exportBtn.style.display = '';
         exportBtn.onclick = function() {
           window.location = `/sigma/export/${encodeURIComponent(selectedFolderPath)}`;
         };
       } else {
         exportBtn.style.display = 'none';
       }
     }
     const origSelectFolder = selectFolder;
     selectFolder = function(folderPath) {
       origSelectFolder(folderPath);
       updateExportBtn();
     };
     updateExportBtn();
   });

   document.addEventListener('DOMContentLoaded', function() {
  Prism.highlightAll();

  var clipboard = new ClipboardJS('#copy-btn');
  clipboard.on('success', function(e) {
    var toast = document.getElementById('copy-toast');
    var btn = document.getElementById('copy-btn');
    var label = document.getElementById('copy-btn-label');
    toast.style.display = 'block';
    btn.classList.add('copy-btn-animate');
    label.textContent = 'Copied!';
    setTimeout(function() {
      toast.style.display = 'none';
      btn.classList.remove('copy-btn-animate');
      label.textContent = 'Copy Rule';
    }, 1200);
    e.clearSelection();
  });
  clipboard.on('error', function() {
    alert('Copy failed. Please copy manually.');
  });

  // Keyboard shortcut: Ctrl/Cmd+C when code is focused
  document.getElementById('rule-content').addEventListener('keydown', function(e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'c') {
      document.getElementById('copy-btn').click();
      e.preventDefault();
    }
  });
});