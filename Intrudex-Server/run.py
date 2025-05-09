import os

import webview
from dotenv import load_dotenv
from screeninfo import get_monitors

from app import create_app

# Load environment variables
load_dotenv()

# Create Flask app
app = create_app()

# Determine app mode
mode = os.getenv("MODE", "development").lower()

# Get screen size using screeninfo
def get_screen_size():
    try:
        monitor = get_monitors()[0]
        return monitor.width, monitor.height
    except:
        return 1920, 1080

def is_running_in_docker():
    return os.path.exists('/.dockerenv')

if __name__ == '__main__':
    port = int(os.getenv('FLASK_RUN_PORT', 5000))
    host = os.getenv('FLASK_RUN_HOST', '127.0.0.1')
    debug = bool(int(os.getenv('FLASK_DEBUG', 1)))

    if is_running_in_docker():
        app.run(host='0.0.0.0', port=port, debug=debug)
    elif mode == 'production':
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
    else:
        app.run(host=host, port=port, debug=debug)
