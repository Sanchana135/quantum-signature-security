import os
from app import create_app

app = create_app(os.environ.get("FLASK_ENV", "development"))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    debug = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1", "t")

    print("=" * 80)
    print("  QUANTUM-SHIELD // CYBER THREAT DETECTION FOR DIGITAL SIGNATURE SECURITY")
    print("=" * 80)
    print(f"  * Environment: {os.environ.get('FLASK_ENV', 'development')}")
    print(f"  * Local URL:   http://{host}:{port}")
    print("  * Demo Login:  demo_analyst / CyberSec#2026!")
    print("=" * 80)

    app.run(host=host, port=port, debug=debug)
