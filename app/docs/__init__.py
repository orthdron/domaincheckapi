from flask import Blueprint

docs_bp = Blueprint('docs', __name__)

from . import routes  # noqa 