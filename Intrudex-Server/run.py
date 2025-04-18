import os
import webview
from app import create_app
from dotenv import load_dotenv
from screeninfo import get_monitors

# Load environment variables
load_dotenv()

# Create Flask app
app = create_app()

# Determine app mode
mode = os.getenv("MODE", "development").lower()

# Get screen size using screeninfo
def get_screen_size():
    monitor = get_monitors()[0]  # Get primary monitor
    return monitor.width, monitor.height

if __name__ == '__main__':
    port = int(os.getenv('FLASK_RUN_PORT', 5000))
    host = os.getenv('FLASK_RUN_HOST', '127.0.0.1')
    debug = bool(int(os.getenv('FLASK_DEBUG', 1)))

    if mode == "development":
        app.run(host=host, port=port, debug=debug)
    else:
        width, height = get_screen_size()
        window = webview.create_window(
            'Intrudex Server',
            app,
            width=width,
            height=height,
            resizable=True,
            fullscreen=False
        )
        webview.start()
