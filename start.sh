#!/bin/bash
source /app/.venv/bin/activate
export PYTHONPATH=/app
export FLASK_APP=script.py
export FLASK_ENV=production

# Wait for Redis if configured
if [ ! -z "$REDIS_URL" ]; then
    echo "Waiting for Redis..."
    timeout 30 bash -c 'until printf "" 2>>/dev/null >>/dev/tcp/$0/$1; do sleep 1; done' $(echo $REDIS_URL | cut -d/ -f3 | tr ":" " ")
fi

# Start the application
exec gunicorn script:app \
    --bind 0.0.0.0:${PORT:-3000} \
    --workers ${GUNICORN_WORKERS:-4} \
    --timeout ${GUNICORN_TIMEOUT:-30} \
    --access-logfile - \
    --error-logfile - \
    --log-level ${LOG_LEVEL:-info} 