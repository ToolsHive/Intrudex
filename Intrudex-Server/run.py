import os
from app import create_app
from dotenv import load_dotenv

load_dotenv()

app = create_app()

if __name__ == '__main__':
    port = int(os.getenv('FLASK_RUN_PORT', 80))
    host = os.getenv('FLASK_RUN_HOST', '127.0.0.1')
    debug = bool(int(os.getenv('FLASK_DEBUG', 1)))

    app.run(host=host, port=port, debug=debug)