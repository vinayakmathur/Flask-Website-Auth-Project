from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager

db = SQLAlchemy()
DB_NAME = "database.db"

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'abcde'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)

    


    from .views import views
    from .auth import auth
    app.register_blueprint(views)
    app.register_blueprint(auth)

    from .models import User, Note

    # Create the database inside app context
    with app.app_context():
        create_database()
        login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader

    def load_user(id):
        return User.query.get(int(id))


    return app


def create_database():
    if not path.exists('website/' + DB_NAME):
        db.create_all()
        print('Database Created!')
