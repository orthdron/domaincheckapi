import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # Development server only; production runs gunicorn (see gunicorn.conf.py).
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "3000")))
