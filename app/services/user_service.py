from app.models import User 
from app.extensions import db 

class UserService:
    @staticmethod 
    def create_user(username, password):
        if User.query.filter_by(username=username).first():
            raise ValueError("Username already exists")
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def authenticate(username, password):
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            return user
        return None