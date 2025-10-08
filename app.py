from flask import Flask, jsonify, request, abort 
from flask_sqlalchemy import SQLAlchemy 
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
     jwt_required, get_jwt_identity, get_jwt
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta 


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-key' 
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)

db = SQLAlchemy(app)
jwt = JWTManager(app)

revoked_tokens = set()

@app.cli.command()
def reset_db():
    """Drop all tables and recreate them."""
    db.drop_all()
    db.create_all()
    print("Database reset successfully!")


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    tasks = db.relationship('Tasks', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    done= db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


    def to_dict(self):
        return {"id": self.id, "title": self.title, "done": self.done}

with app.app_context():
    db.create_all()


@jwt.token_in_blocklist_loader 
def check_if_token_revoked(jwt_header, jwt_payload):
    return jwt_payload['jti'] in revoked_tokens

@jwt.revoked_token_loader 
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({'msg': 'Token has been revoked'}), 401


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        abort(400, description='Username and Password is required')

    if User.query.filter_by(username=data['username']).first():
        abort(400, description='Username already exists')

    user = User(username=data['username'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()

    return jsonify(message='User registered successfully'), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        abort(400, description='Username and password required')

    user = User.query.filter_by(username=data['username']).first()
    if not user or not user.check_password(data['password']):
        abort(401, description='Invalid credentials')


    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))
    return jsonify(access_token=token, refresh_token=refresh_token)


 @app.route('/refresh', methods=['POST'])
 @jwt_required(refresh=True)
 def refresh_access_token():
    user_id = get_jwt_identity()
    access_token = create_access_token(identity=str(user_id))
    return jsonify(access_token=access_token)

@app.route('/logout', methods=['POST'])
@jwt_required(verify_type=False)
def logout():
    jti = get_jwt()['jti']
    revoked_tokens.add(jti)
    return jsonify(msg='Successfully log out'), 200

@app.route('/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    user_id = get_jwt_identity()
    query = Tasks.query.filter_by(user_id=user_id)

    # query params
    done_param = request.args.get('done')
    page = request.args.get('page', default=1, type=int)
    limit = request.args.get('limit', default=5, type=int)
    search_query = request.args.get('q')
    sort_param = request.args.get('sort', 'id')

    #query = Tasks.query

    #filtering by done
    if done_param is not None:
        if done_param.lower() in ['true', '1', 'yes']:
            query = query.filter_by(done=True)
        elif done_param.lower() in ['false', '0', 'no']:
            query = query.filter_by(done=False)

    # searching in title
    if search_query:
        query = query.filter(Tasks.title.ilike(f"%{search_query}%"))

    #sorting 
    if sort_param.startswith('-'):
        field = sort_param[1:]
        desc = True 
    else:
        field = sort_param
        desc = False 

    if hasattr(Tasks, field):
        column = getattr(Tasks, field)
        query = query.order_by(column.desc() if desc else column.asc())
    else:
        abort(400, description=f"Invalid sort field: {field}")

    paginated = query.paginate(page=page, per_page=limit, error_out=False)

    print(paginated)
    
    return jsonify({
        "page": page,
        "limit": limit,
        "total": paginated.total,
        "pages": paginated.pages,
        "tasks": [t.to_dict() for t in paginated.items]
    })

@app.route('/tasks/<int:task_id>', methods=['GET'])
@jwt_required()
def get_task(task_id):
    user_id = get_jwt_identity()
    task = Tasks.query.filter_by(id=task_id, user_id=user_id).first_or_404()
    #task = Tasks.query.get_or_404(task_id)
    return jsonify(task.to_dict())


@app.route('/tasks', methods=['POST'])
@jwt_required()
def create_task():
    user_id = get_jwt_identity()

    data = request.get_json() 
    if not data or 'title' not in data:
        abort(400, description='Missing title in request data')

    task = Tasks(title=data['title'], done=data.get('done', False), user_id=user_id)
    db.session.add(task)
    db.session.commit()

    return jsonify(task.to_dict()), 201 

@app.route('/tasks/<int:task_id>', methods=['PUT'])
@jwt_required()
def update_task(task_id):
    user_id = get_jwt_identity()
    #task = Tasks.query.get_or_404(task_id)
    task = Tasks.query.filter_by(id=task_id, user_id=user_id).first_or_404()
    
    data = request.get_json()
    if not data:
        abort(400, description="Missing JSON data")

    task.title = data.get('title', task.title)
    task.done = data.get('done', task.done)

    db.session.commit()
    return jsonify(task.to_dict())

@app.route('/tasks/<int:task_id>', methods=['DELETE']) 
@jwt_required()
def delete_task(task_id):
    user_id = get_jwt_identity()
    #task = Tasks.query.get_or_404(task_id)
    task = Task.query.filter_by(id=task_id, user_id=user_id).first_or_404()
    db.session.delete(task)
    db.session.commit()
    return '', 204 


if __name__ == '__main__':
    app.run(debug=True)


