import ctypes
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import subprocess
import os
import threading
import shutil
import json
import sys
import time

SETTINGS_FILE = os.path.join(os.getenv('LOCALAPPDATA', os.getcwd()), 'IntrudexBuilder', 'settings.json')
os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)

try:
    from winotify import Notification
    HAS_WINOTIFY = True
except ImportError:
    HAS_WINOTIFY = False

# Catppuccin Mocha color scheme
COLORS = {
    'rosewater': '#f2d5d5',
    'flamingo': '#eebebe',
    'pink': '#f0bcea',
    'mauve': '#b889f4',
    'red': '#ec6a88',
    'maroon': '#d85e72',
    'peach': '#f8a47f',
    'yellow': '#f8e3a3',
    'green': '#99d6a2',
    'teal': '#7bd3c3',
    'sky': '#74c5db',
    'sapphire': '#5ab0d8',
    'blue': '#4e9dd9',

    'text': '#c6d0f5',
    'subtext1': '#a4acc9',
    'subtext0': '#939ab7',

    'overlay2': '#7e85a2',
    'overlay1': '#6a708f',
    'overlay0': '#5a5f77',

    'surface2': '#44475a',
    'surface1': '#343645',
    'surface0': '#2b2d3a',

    'base': '#1a1b26',
    'mantle': '#15161e',
    'crust': '#0e0f16',

    'success_hover': '#6fd3b9',
    'error_hover': '#d75f71',
    'selection': '#5b9df8',

    'terminal_bg': '#1a1b26',
    'terminal_fg': '#c6d0f5',
    'border': '#313244',
    'white': '#ffffff'
}


# Custom styles for ttk widgets
def apply_custom_styles():
    style = ttk.Style()
    style.theme_use('default')  # Ensure consistent base

    # Frame styling
    style.configure('Card.TFrame', background=COLORS['surface0'])
    style.configure('TFrame', background=COLORS['base'])  # fallback

    # Notebook (tabbed output)
    style.configure('Terminal.TNotebook', background=COLORS['base'], borderwidth=0)
    style.configure('Terminal.TNotebook.Tab',
                    background=COLORS['surface0'],
                    foreground=COLORS['text'],
                    padding=[10, 5],
                    borderwidth=0)
    style.map('Terminal.TNotebook.Tab',
              background=[('selected', COLORS['surface1'])],
              foreground=[('selected', COLORS['blue'])])

    # Combobox
    style.configure('Custom.TCombobox',
                    background=COLORS['surface0'],
                    fieldbackground=COLORS['surface1'],
                    foreground=COLORS['text'],
                    arrowcolor=COLORS['blue'],
                    borderwidth=0)

    # LabelFrame styling (source/build path sections)
    style.configure('Custom.TLabelframe',
                    background=COLORS['surface0'],
                    foreground=COLORS['text'],
                    borderwidth=1)
    style.configure('Custom.TLabelframe.Label',
                    background=COLORS['surface0'],
                    foreground=COLORS['text'],
                    font=("Segoe UI", 9, "bold"))

    # Progressbar
    style.configure('Custom.Horizontal.TProgressbar',
                    troughcolor=COLORS['surface0'],
                    background=COLORS['blue'],
                    bordercolor=COLORS['surface2'],
                    lightcolor=COLORS['blue'],
                    darkcolor=COLORS['sapphire'])

# Custom button class with hover effect
class HoverButton(tk.Button):
    def __init__(self, master=None, hover_color=None, **kwargs):
        super().__init__(master, **kwargs)
        self.default_color = kwargs.get('bg', 'white')
        self.hover_color = hover_color or self.default_color
        
        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)
        
    def on_enter(self, e):
        self['bg'] = self.hover_color
        
    def on_leave(self, e):
        self['bg'] = self.default_color

# Check for admin privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Elevate to admin if needed
def run_as_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        sys.exit()

def show_notification(title, msg):
    try:
        if HAS_WINOTIFY:
            toast = Notification(
                app_id="Intrudex Builder",
                title=title,
                msg=msg,
                icon=None
            )
            toast.show()
            return
    except Exception as e:
        print(f"Toast notification failed: {e}")

    # Fallback to MessageBox
    try:
        MB_ICONINFORMATION = 0x40
        ctypes.windll.user32.MessageBoxW(None, msg, title, MB_ICONINFORMATION)
    except Exception as e:
        print(f"Fallback MessageBox failed: {e}")
        print(f"{title}: {msg}")

def build_project():
    folder = source_folder.get()
    build_type = build_type_var.get()
    thread_count = thread_count_var.get()
    compress_upx = upx_var.get()
    clean_build = clean_var.get()
    copy_to_desktop = copy_var.get()

    if not folder or not os.path.exists(folder):
        log_output("❌ Invalid source folder path.")
        show_notification("Intrudex Builder", "Invalid source folder path.")
        return

    # Use custom build directory if specified, otherwise use default
    build_dir = build_folder.get()
    if not build_dir:
        build_dir = os.path.join(folder, "build")
    build_folder.set(build_dir)  # Update UI with final path
    
    # Print build header with improved formatting
    header = """
╔════════════════════════════════════════════════════════════════╗
║                 🛡️  INTRUDEX CLIENT BUILD                      ║
╚════════════════════════════════════════════════════════════════╝"""
    log_output(header)
    log_output("")  # Empty line for better readability
    # Build configuration summary with improved formatting
    config_info = f"""
📋 Build Configuration:
  • Time        : {time_now()}
  • Source      : {folder}
  • Output      : {build_dir}
  • Type        : {build_type}
  • Threads     : {thread_count}
  • Clean Build : {'✅' if clean_build else '❌'}
  • UPX        : {'✅' if compress_upx else '❌'}
  • Copy       : {'✅' if copy_to_desktop else '❌'}
──────────────────────────────────────────────────────────────────"""
    log_output(config_info)
    show_notification("Intrudex Builder", f"Build process started with {build_type} configuration")

    progress_var.set(10)
    status_var.set("Preparing build environment...")
    app.update_idletasks()

    # Clean build with improved safety checks and force-kill handle approach
    if clean_build:
        log_output("\n🧹 Cleaning build environment...")
        try:
            if os.path.exists(build_dir):
                log_output("   Removing existing build directory...")
                if force_remove_path(build_dir):
                    log_output("✅ Build directory cleaned successfully")
                else:
                    log_output("⚠️ Warning: Could not completely clean build directory")
            
            # Recreate build directory
            os.makedirs(build_dir, exist_ok=True)
            log_output("✅ Created fresh build directory")
        except Exception as e:
            log_output(f"⚠️ Warning: Clean operation partial - {str(e)}")
            # Try to ensure the build directory exists even if cleaning failed
            os.makedirs(build_dir, exist_ok=True)
        
        progress_var.set(20)
        status_var.set("Build directory cleaned")
    else:
        # Remove CMake cache files
        for cache_file in ["CMakeCache.txt", "CMakeFiles"]:
            cache_path = os.path.join(build_dir, cache_file)
            if os.path.exists(cache_path):
                try:
                    if os.path.isdir(cache_path):
                        shutil.rmtree(cache_path, ignore_errors=True)
                    else:
                        os.remove(cache_path)
                    log_output(f"Removed cache file: {cache_file}")
                except Exception as e:
                    log_output(f"Error removing cache file: {e}")
        progress_var.set(20)
        status_var.set("CMake cache cleared")
    app.update_idletasks()

    progress_var.set(30)
    status_var.set("Configuring project with CMake...")
    app.update_idletasks()
    # CMake configuration with improved output
    log_output("\n⚙️  Configuring CMake build...")
    cmake_cmd = [
        "cmake",
        "-S", folder,
        "-B", build_dir,
        "-G", "MinGW Makefiles",
        f"-DCMAKE_BUILD_TYPE={build_type}",
        f"-DCMAKE_RUNTIME_OUTPUT_DIRECTORY={build_dir}",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"  # For better error reporting
    ]
    log_output("   Running: cmake configure...")
    try:
        run_command(cmake_cmd)
        log_output("✅ CMake configuration successful")
    except Exception as e:
        log_output("❌ CMake configuration failed")
        raise

    progress_var.set(50)
    status_var.set("Building project...")
    app.update_idletasks()
    # Build process with improved output
    log_output("\n🔨 Building project...")
    build_cmd = [
        "cmake",
        "--build", build_dir,
        "--config", build_type,
        "-j", thread_count,
        "--", "-k"  # Keep going if possible
    ]
    
    try:
        log_output(f"   Compiling with {thread_count} threads...")
        run_command(build_cmd)
        log_output("✅ Build process completed")
    except Exception as e:
        log_output("❌ Build process failed")
        log_output("\n⚠️  Build Error Details:")
        log_output(f"   {str(e)}")
        
        # Try to find and show compile_commands.json for better error info
        compile_commands = os.path.join(build_dir, "compile_commands.json")
        if os.path.exists(compile_commands):
            log_output("\nℹ️  Additional build information available in:")
            log_output(f"   {compile_commands}")
        raise

    progress_var.set(80)
    status_var.set("Build completed, processing output...")
    app.update_idletasks()
    # Find executable
    exe = None
    for root, dirs, files in os.walk(build_dir):
        for file in files:
            if file.endswith('.exe'):
                exe = os.path.join(root, file)
                break
        if exe:
            break
    if exe:
        log_output("📋 Executable Information:")
        log_output(f"   Path: {exe}")
        log_output(f"   Size: {round(os.path.getsize(exe)/1_048_576,2)} MB")
        log_output(f"   Created: {time_now()}")
        # UPX Compression
        if compress_upx:
            upx_path = shutil.which("upx")
            if not upx_path:
                log_output("❌ UPX not found in PATH")
                log_output("   Please install UPX or add it to your PATH")
                show_notification("UPX not found", "Skipping compression")
            else:
                log_output(f"✅ UPX found at: {upx_path}")
                original_size = os.path.getsize(exe)
                log_output(f"   Original size: {round(original_size/1_048_576,2)} MB")
                log_output("   Compressing executable...")
                upx_cmd = [upx_path, "--best", "--ultra-brute", exe]
                run_command(upx_cmd)
                new_size = os.path.getsize(exe)
                compression_ratio = ((original_size - new_size) / original_size) * 100
                log_output(f"✅ UPX compression successful!")
                log_output(f"   Compressed size: {round(new_size/1_048_576,2)} MB")
                log_output(f"   Compression ratio: {compression_ratio:.1f}%")
                show_notification("UPX compression", f"{compression_ratio:.1f}% reduction")
        # Copy to desktop
        if copy_to_desktop:
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            dest_file = os.path.join(desktop, os.path.basename(exe))
            try:
                shutil.copy2(exe, dest_file)
                log_output(f"✅ Successfully copied to: {dest_file}")
                show_notification("Executable copied", "Copied to desktop")
            except Exception as e:
                log_output(f"❌ Failed to copy to desktop: {e}")
                show_notification("Copy failed", "Failed to copy to desktop")
        total_time = time_now()
        log_output("═══════════════════════════════════════════════════════════════")
        log_output("🎉 BUILD COMPLETED SUCCESSFULLY!")
        log_output(f"   Final executable: {exe}")
        log_output(f"   Build configuration: {build_type}")
        log_output("═══════════════════════════════════════════════════════════════")
        progress_var.set(100)
        status_var.set("Build completed successfully!")
        show_notification("Build completed", "Build completed successfully!")
    else:
        log_output("❌ No executable found in build directory")
        log_output(f"   Searched in: {build_dir}")
        show_notification("No executable found", "Build failed")
        status_var.set("Build failed")

    # Save settings
    settings = {
        'source': folder,
        'build': build_dir,
        'buildType': build_type,
        'threadCount': thread_count,
        'compressUPX': compress_upx,
        'cleanBuild': clean_build,
        'copyToDesktop': copy_to_desktop
    }
    try:
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(settings, f)
        log_output("Settings saved for next session")
    except Exception as e:
        log_output(f"Could not save settings: {e}")

def run_command(cmd, cwd=None):
    try:
        # Show command being executed in terminal
        cmd_str = ' '.join(cmd)
        log_output(f"\n$ {cmd_str}", is_terminal=True)
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            shell=False,
            universal_newlines=True
        )
        
        # Handle output in real-time
        while True:
            output = process.stdout.readline()
            error = process.stderr.readline()
            
            if output:
                output = output.strip()
                log_output(output, is_terminal=True)
                if any(s in output.lower() for s in ['error', 'failed', 'fatal']):
                    log_output(f"❌ {output}")  # Also show in build log
                elif 'warning' in output.lower():
                    log_output(f"⚠️ {output}")  # Also show in build log
            
            if error:
                error = error.strip()
                log_output(error, is_terminal=True)
                log_output(f"❌ {error}")  # Also show in build log
            
            if output == '' and error == '' and process.poll() is not None:
                break
        
        process.wait()
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, cmd)
            
    except Exception as e:
        error_msg = f"❌ Error: {str(e)}"
        log_output(error_msg)
        log_output(error_msg, is_terminal=True)

# Performance improvements
def debounce(wait):
    """Decorator to debounce a function"""
    def decorator(fn):
        last_call = [0]
        timer = [None]
        
        def debounced(*args, **kwargs):
            def call_it():
                fn(*args, **kwargs)
                last_call[0] = time.time()
            
            if timer[0] is not None:
                timer[0].cancel()
                
            if time.time() - last_call[0] >= wait:
                call_it()
            else:
                timer[0] = threading.Timer(wait - (time.time() - last_call[0]), call_it)
                timer[0].start()
                
        return debounced
    return decorator

# Apply debouncing to UI updates
@debounce(0.1)
def update_status(message):
    status_var.set(message)
    app.update_idletasks()

# Optimize log output
def log_output(message, is_terminal=False):
    widget = terminal_box if is_terminal else log_box
    
    def update():
        widget.config(state=tk.NORMAL)
        if isinstance(message, str):
            if '✅' in message or 'successful' in message.lower():
                widget.insert(tk.END, message + "\n", 'success')
            elif '❌' in message or 'error' in message.lower() or 'failed' in message.lower():
                widget.insert(tk.END, message + "\n", 'error')
                if is_terminal:
                    output_notebook.select(1)
            elif '⚠️' in message or 'warning' in message.lower():
                widget.insert(tk.END, message + "\n", 'warning')
            elif '📋' in message or 'ℹ️' in message:
                widget.insert(tk.END, message + "\n", 'info')
            else:
                widget.insert(tk.END, message + "\n")
        else:
            widget.insert(tk.END, str(message) + "\n")
        
        # Only scroll if near the bottom
        if float(widget.yview()[1]) > 0.9:
            widget.see(tk.END)
        widget.config(state=tk.DISABLED)
    
    app.after(0, update)  # Schedule update in main thread

def browse_folder():
    path = filedialog.askdirectory()
    if path:
        source_folder.set(path)

# Function to browse for build directory
def browse_build_folder():
    path = filedialog.askdirectory()
    if path:
        build_folder.set(path)
        
def start_build_thread():
    threading.Thread(target=build_project, daemon=True).start()


# GUI Setup with modern styling
app = tk.Tk()
app.title("INTRUDEX Client Builder")
app.geometry("1080x960")
app.configure(bg=COLORS['base'])
style = ttk.Style()
style.configure('.', background=COLORS['base'], foreground=COLORS['text'])
app.resizable(True, True)

# Variables
source_folder = tk.StringVar()
build_folder = tk.StringVar()  # Build directory variable
build_type_var = tk.StringVar(value="Release")
thread_count_var = tk.StringVar(value="4")
upx_var = tk.BooleanVar(value=False)
clean_var = tk.BooleanVar(value=False)
copy_var = tk.BooleanVar(value=False)
progress_var = tk.IntVar(value=0)
status_var = tk.StringVar(value="Ready to build")

# Load settings
if os.path.exists(SETTINGS_FILE):
    try:
        with open(SETTINGS_FILE, 'r') as f:
            last = json.load(f)
        if last.get('source'): source_folder.set(last['source'])
        if last.get('build'): build_folder.set(last['build'])
        if last.get('buildType'): build_type_var.set(last['buildType'])
        if last.get('threadCount'): thread_count_var.set(str(last['threadCount']))
        if last.get('compressUPX') is not None: upx_var.set(last['compressUPX'])
        if last.get('cleanBuild') is not None: clean_var.set(last['cleanBuild'])
        if last.get('copyToDesktop') is not None: copy_var.set(last['copyToDesktop'])
    except Exception: pass

# Apply custom styles
apply_custom_styles()

# Configure grid weights for better resizing
app.grid_columnconfigure(0, weight=1)
app.grid_rowconfigure(0, weight=1)

# Helper function for time
def time_now():
    import datetime
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Custom frame with hover effect
class HoverFrame(tk.Frame):
    def __init__(self, master=None, hover_bg=None, **kwargs):
        super().__init__(master, **kwargs)
        self.default_bg = kwargs.get('bg', COLORS['surface0'])
        self.hover_bg = hover_bg or COLORS['surface1']
        
        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)
        
    def on_enter(self, e):
        self.configure(bg=self.hover_bg)
        
    def on_leave(self, e):
        self.configure(bg=self.default_bg)

# This section will be removed

# Load settings
if os.path.exists(SETTINGS_FILE):
    try:
        with open(SETTINGS_FILE, 'r') as f:
            last = json.load(f)
        if last.get('source'): source_folder.set(last['source'])
        if last.get('build'): build_folder.set(last['build'])
        if last.get('buildType'): build_type_var.set(last['buildType'])
        if last.get('threadCount'): thread_count_var.set(str(last['threadCount']))
        if last.get('compressUPX') is not None: upx_var.set(last['compressUPX'])
        if last.get('cleanBuild') is not None: clean_var.set(last['cleanBuild'])
        if last.get('copyToDesktop') is not None: copy_var.set(last['copyToDesktop'])
    except Exception: pass

# Top Title with anime-inspired styling
title_frame = tk.Frame(app, bg=COLORS['base'])
title_frame.pack(pady=8)
tk.Label(title_frame, 
         text="🛡️ Intrudex Builder ✨", 
         font=("Segoe UI", 16, "bold"), 
         bg=COLORS['base'], 
         fg=COLORS['blue']).pack()
tk.Label(title_frame, 
         text="Advanced Build System", 
         font=("Segoe UI", 9), 
         bg=COLORS['base'], 
         fg=COLORS['subtext1']).pack()

# Source Path with DND support
src_frame = ttk.LabelFrame(app, text="📂 Source Path", style="Custom.TLabelframe")
src_frame.pack(pady=4, padx=10, fill=tk.X)

src_inner_frame = tk.Frame(src_frame, bg=COLORS['surface0'], padx=4, pady=4)
src_inner_frame.pack(fill=tk.X, expand=True)

entry_frame = tk.Frame(src_inner_frame, bg=COLORS['surface0'])
entry_frame.pack(fill=tk.X, expand=True, pady=(4, 0))

src_entry = tk.Entry(entry_frame, 
                    textvariable=source_folder, 
                    width=70, 
                    font=("Cascadia Code", 10), 
                    bg=COLORS['surface1'], 
                    fg=COLORS['text'],
                    insertbackground=COLORS['text'],
                    selectbackground=COLORS['selection'],
                    selectforeground=COLORS['text'])
src_entry.pack(side=tk.LEFT, padx=(0, 8), fill=tk.X, expand=True)

# Browse button with modern styling
browse_btn = HoverButton(src_frame, 
                        text="📁 Browse",
                        command=browse_folder,
                        font=("Segoe UI", 9),
                        bg=COLORS['blue'],
                        fg=COLORS['white'],
                        activebackground=COLORS['selection'],
                        activeforeground=COLORS['white'],
                        relief=tk.FLAT,
                        padx=12,
                        pady=4)
browse_btn.pack(side=tk.LEFT, padx=4)

# Build Settings Container
settings_container = HoverFrame(app, bg=COLORS['surface0'], hover_bg=COLORS['surface1'])
settings_container.pack(pady=(20, 0), padx=20, fill=tk.X)

# Inner frame with border and padding
settings_inner = tk.Frame(settings_container,
                         bg=COLORS['surface0'],
                         highlightthickness=1,
                         highlightbackground=COLORS['border'],
                         padx=15, pady=15)
settings_inner.pack(fill=tk.X, padx=5, pady=5)

# Build Configuration Section
config_frame = tk.Frame(settings_inner, bg=COLORS['surface0'])
config_frame.pack(fill=tk.X, expand=True)

# Build Type Selection
build_type_frame = tk.Frame(config_frame, bg=COLORS['surface0'])
build_type_frame.pack(side=tk.LEFT, padx=(0, 16))

tk.Label(build_type_frame, 
         text="⚙️ Configuration", 
         font=("Segoe UI", 10), 
         fg=COLORS['text'], 
         bg=COLORS['surface0']).pack(anchor='w')

build_type_cb = ttk.Combobox(build_type_frame, 
                            textvariable=build_type_var,
                            values=["Release", "Debug", "RelWithDebInfo", "MinSizeRel"],
                            font=("Cascadia Code", 9),
                            width=18,
                            style='Custom.TCombobox',
                            state="readonly")
build_type_cb.pack(pady=4)

# Thread Count Selection
thread_frame = tk.Frame(config_frame, bg=COLORS['surface0'])
thread_frame.pack(side=tk.LEFT)

tk.Label(thread_frame,
         text="🧵 Threads",
         font=("Segoe UI", 10),
         fg=COLORS['text'],
         bg=COLORS['surface0']).pack(anchor='w')

thread_count_cb = ttk.Combobox(thread_frame,
                              textvariable=thread_count_var,
                              values=["1", "2", "4", "8", "16"],
                              font=("Cascadia Code", 9),
                              width=8,
                              style='Custom.TCombobox',
                              state="readonly")
thread_count_cb.pack(pady=4)

# Separator
tk.Frame(settings_inner, height=2, bg=COLORS['border']).pack(fill=tk.X, pady=15)

# Build Options
options_frame = tk.Frame(settings_inner, bg=COLORS['surface0'])
options_frame.pack(fill=tk.X)

tk.Label(options_frame,
         text="🔧 Options",
         font=("Segoe UI", 10),
         fg=COLORS['text'],
         bg=COLORS['surface0']).pack(anchor='w', pady=(0, 6))

# Checkbuttons with hover effect
def create_hover_checkbutton(parent, text, variable):
    frame = tk.Frame(parent, bg=COLORS['surface0'])
    frame.pack(side=tk.LEFT, padx=8)
    
    cb = tk.Checkbutton(frame,
                        text=text,
                        variable=variable,
                        font=("Segoe UI", 9),
                        bg=COLORS['surface0'],
                        fg=COLORS['text'],
                        selectcolor=COLORS['surface1'],
                        activebackground=COLORS['surface1'],
                        cursor="hand2")
    cb.pack()
    
    return cb

# Create enhanced checkbuttons with more compact layout
upx_cb = create_hover_checkbutton(options_frame, "🔧 UPX", upx_var)
clean_cb = create_hover_checkbutton(options_frame, "🧹 Clean", clean_var)
copy_cb = create_hover_checkbutton(options_frame, "📋 Copy", copy_var)

# Build Controls Container
build_control_frame = HoverFrame(app, bg=COLORS['surface0'], hover_bg=COLORS['surface1'])
build_control_frame.pack(pady=20, padx=20, fill=tk.X)

# Inner frame with border
build_inner_frame = tk.Frame(build_control_frame, 
                           bg=COLORS['surface0'],
                           highlightthickness=1,
                           highlightbackground=COLORS['border'],
                           padx=15, pady=15)
build_inner_frame.pack(fill=tk.X, padx=5, pady=5)

# Build Button with anime-inspired styling
build_btn = HoverButton(build_inner_frame, 
                       text="✨ BUILD ✨",
                       command=start_build_thread,
                       font=("Segoe UI", 12, "bold"),
                       bg=COLORS['blue'],
                       fg=COLORS['base'],
                       hover_color=COLORS['sapphire'],
                       relief=tk.FLAT,
                       cursor="hand2",
                       padx=20,
                       pady=8)
build_btn.pack(pady=(0, 8))

# Progress & Status container
status_frame = tk.Frame(build_inner_frame, bg=COLORS['surface0'])
status_frame.pack(fill=tk.X, expand=True)

# Status with anime-inspired icon
status_label = tk.Label(status_frame,
                       textvariable=status_var,
                       font=("Segoe UI", 9),
                       fg=COLORS['text'],
                       bg=COLORS['surface0'])
status_label.pack(side=tk.LEFT, padx=8)

# Enhanced progress bar with gradient effect
progress_bar = ttk.Progressbar(status_frame,
                             variable=progress_var,
                             maximum=100,
                             length=250,
                             mode='determinate',
                             style='Custom.Horizontal.TProgressbar')
progress_bar.pack(side=tk.LEFT, padx=8, fill=tk.X, expand=True)

# Output container with notebook for log and terminal
output_container = ttk.Frame(app, style='Card.TFrame')
output_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))

# Create notebook for log/terminal tabs
output_notebook = ttk.Notebook(output_container, style='Terminal.TNotebook')
output_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

# Build Log tab
log_frame = ttk.Frame(output_notebook, style='Card.TFrame')
output_notebook.add(log_frame, text=' 📋 Build Log ')

# Terminal Output tab
terminal_frame = ttk.Frame(output_notebook, style='Card.TFrame')
output_notebook.add(terminal_frame, text=' 🖥️ Terminal Output ')

# Log Header (fix log_inner reference)
log_header = tk.Frame(log_frame, bg=COLORS['surface0'])
log_header.pack(fill=tk.X, pady=(0, 10))

tk.Label(log_header,
         text="",
         font=("JetBrains Mono", 14, "bold"),
         fg=COLORS['text'],
         bg=COLORS['surface0']).pack(side=tk.LEFT)

# Log Controls in header
log_ctrl_frame = tk.Frame(log_header, bg=COLORS['surface0'])
log_ctrl_frame.pack(side=tk.RIGHT)

def clear_log():
    log_box.config(state=tk.NORMAL)
    log_box.delete(1.0, tk.END)
    log_box.config(state=tk.DISABLED)
    log_output("Log cleared")

def save_log():
    file = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        title="Save Build Log"
    )
    if file:
        with open(file, 'w', encoding='utf-8') as f:
            f.write(log_box.get(1.0, tk.END))
        log_output(f"Log saved to: {file}")

# Enhanced control buttons
clear_btn = HoverButton(log_ctrl_frame,
                       text="🗑️ Clear",
                       command=clear_log,
                       font=("Segoe UI", 9),
                       bg=COLORS['red'],
                       hover_color=COLORS['error_hover'],
                       fg=COLORS['white'],
                       relief=tk.FLAT,
                       cursor="hand2",
                       padx=10,
                       pady=3)
clear_btn.pack(side=tk.LEFT, padx=4)

save_btn = HoverButton(log_ctrl_frame,
                      text="💾 Save",
                      command=save_log,
                      font=("Segoe UI", 9),
                      bg=COLORS['peach'],
                      hover_color=COLORS['yellow'],
                      fg=COLORS['white'],
                      relief=tk.FLAT,
                      cursor="hand2",
                      padx=10,
                      pady=3)
save_btn.pack(side=tk.LEFT, padx=4)

# Build Log
log_box = scrolledtext.ScrolledText(
    log_frame,
    font=("Cascadia Code", 9),
    bg=COLORS['base'],
    fg=COLORS['text'],
    insertbackground=COLORS['text'],
    selectbackground=COLORS['selection'],
    selectforeground=COLORS['white'],
    state=tk.DISABLED,
    padx=4,
    pady=4,
    wrap=tk.WORD
)
log_box.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

# Terminal output
terminal_box = scrolledtext.ScrolledText(
    terminal_frame,
    font=("Cascadia Code", 9),
    bg=COLORS['terminal_bg'],
    fg=COLORS['terminal_fg'],
    insertbackground=COLORS['text'],
    selectbackground=COLORS['surface1'],
    selectforeground=COLORS['text'],
    state=tk.DISABLED,
    padx=4,
    pady=4
)
terminal_box.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

# Custom tags for colored output
for widget in [log_box, terminal_box]:
    widget.tag_configure('success', foreground=COLORS['green'])
    widget.tag_configure('error', foreground=COLORS['red'])
    widget.tag_configure('warning', foreground=COLORS['yellow'])
    widget.tag_configure('info', foreground=COLORS['blue'])

# Keyboard Shortcuts
def on_key(event):
    if event.keysym == 'F5':
        build_btn.invoke()
    elif event.keysym == 'F1':
        messagebox.showinfo("Help", "🛡️ Intrudex Client Builder - Help\n\nKeyboard Shortcuts:\n• F5 - Start Build\n• F1 - Show this help\n• Ctrl+L - Clear Log\n• Ctrl+S - Save Log\n\nFeatures:\n• Drag & drop folders into path fields\n• Automatic thread count selection\n• UPX compression support\n• Copy to desktop option\n• Clean build option\n• Persistent settings\n\nBuild Types:\n• Release - Optimized for performance\n• Debug - Includes debug symbols\n• RelWithDebInfo - Release with debug info\n• MinSizeRel - Optimized for size")
    elif event.state & 0x4 and event.keysym.lower() == 'l':
        clear_log()
    elif event.state & 0x4 and event.keysym.lower() == 's':
        save_log()
app.bind('<Key>', on_key)

# Tooltips with improved error handling
def add_tooltip(widget, text):
    def on_enter(e):
        try:
            # Ensure any existing tooltip is destroyed first
            on_leave(e)
            # Create new tooltip
            widget.tooltip_window = tk.Toplevel()
            widget.tooltip_window.wm_overrideredirect(True)
            x = widget.winfo_rootx() + 20
            y = widget.winfo_rooty() + 20
            widget.tooltip_window.wm_geometry(f"+{x}+{y}")
            label = tk.Label(widget.tooltip_window, text=text, bg=COLORS['surface1'], fg=COLORS['text'], 
                           font=("JetBrains Mono", 10), relief=tk.SOLID, borderwidth=1)
            label.pack()
        except Exception:
            pass  # Ignore any tooltip creation errors
            
    def on_leave(e):
        try:
            if hasattr(widget, 'tooltip_window') and widget.tooltip_window:
                widget.tooltip_window.destroy()
                widget.tooltip_window = None
        except Exception:
            pass  # Ignore any tooltip destruction errors
            
    widget.bind('<Enter>', on_enter)
    widget.bind('<Leave>', on_leave)
for w in [src_entry, build_type_cb, thread_count_cb, build_btn]:
    if hasattr(w, 'tooltip'):
        add_tooltip(w, w.tooltip)

# After the source path frame, add build path frame
build_frame = ttk.LabelFrame(app, text="🔨 Build Path", style="Custom.TLabelframe")
build_frame.pack(pady=4, padx=10, fill=tk.X)

build_inner_frame = tk.Frame(build_frame, bg=COLORS['surface0'], padx=4, pady=4)
build_inner_frame.pack(fill=tk.X, expand=True)

build_entry_frame = tk.Frame(build_inner_frame, bg=COLORS['surface0'])
build_entry_frame.pack(fill=tk.X, expand=True, pady=(4, 0))

build_entry = tk.Entry(build_entry_frame, 
                    textvariable=build_folder, 
                    width=70, 
                    font=("Cascadia Code", 10), 
                    bg=COLORS['surface1'], 
                    fg=COLORS['text'],
                    insertbackground=COLORS['text'],
                    selectbackground=COLORS['selection'],
                    selectforeground=COLORS['white'])
build_entry.pack(side=tk.LEFT, padx=(0, 8), fill=tk.X, expand=True)

# Build path browse button
build_browse_btn = HoverButton(build_frame, 
                        text="📁 Browse",
                        command=browse_build_folder,
                        font=("Segoe UI", 9),
                        bg=COLORS['blue'],
                        fg=COLORS['white'],
                        activebackground=COLORS['selection'],
                        activeforeground=COLORS['white'],
                        relief=tk.FLAT,
                        padx=12,
                        pady=4)
build_browse_btn.pack(side=tk.LEFT, padx=4)

# Run admin check at start
run_as_admin()

app.mainloop()

def force_remove_path(path):
    """Force remove a file or directory with retries and better error handling."""
    import stat
    import time
    import psutil
    from pathlib import Path

    def on_error(func, path, exc_info):
        """Error handler for shutil.rmtree."""
        try:
            if not os.access(path, os.W_OK):
                os.chmod(path, stat.S_IWUSR)
            func(path)
        except Exception:
            pass

    def kill_processes_locking_path(path):
        """Kill processes that might be locking the path."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    for file in proc.open_files():
                        if path.lower() in file.path.lower():
                            print(f"Terminating process {proc.name()} (PID: {proc.pid})")
                            proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"Warning: Could not check for locking processes: {e}")

    path = Path(path)
    if not path.exists():
        return True

    max_retries = 5
    for attempt in range(max_retries):
        try:
            if path.is_file():
                path.chmod(stat.S_IWRITE)
                path.unlink()
            else:
                # Try to kill processes that might be locking files
                kill_processes_locking_path(str(path))
                time.sleep(0.5)  # Give processes time to terminate

                # Remove read-only flags recursively
                for item in path.rglob("*"):
                    try:
                        item.chmod(stat.S_IWRITE)
                    except Exception:
                        pass

                # Remove the directory tree
                shutil.rmtree(str(path), onerror=on_error)

            return True

        except Exception as e:
            print(f"Attempt {attempt + 1}/{max_retries} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(1 * (attempt + 1))  # Exponential backoff
                continue
            else:
                print(f"Failed to remove {path} after {max_retries} attempts")
                return False

    return False