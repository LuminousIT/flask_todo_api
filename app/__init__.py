from flask import Flask
from .extensions import db, jwt
from .config import Config
from .routes.auth_routes import auth_bp
from .routes.task_routes import task_bp


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(task_bp, url_prefix='/tasks')

    with app.app_context():
        db.create_all()

    return app
