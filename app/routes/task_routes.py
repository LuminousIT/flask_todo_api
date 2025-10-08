from flask import Blueprint, request, jsonify, abort
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import Task
from app.services.task_service import TaskService
from app.extensions import db

task_bp = Blueprint('tasks', __name__)

@task_bp.route('/', methods=['GET'])
@jwt_required()
def list_tasks():
    user_id = get_jwt_identity()
    filters = {
        "done": request.args.get('done'),
        "q": request.args.get('q'),
        "sort": request.args.get('sort', 'id')
    }
    query = TaskService.get_tasks(user_id, filters)
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 5, type=int)
    paginated = query.paginate(page=page, per_page=limit, error_out=False)
    return jsonify({
        "total": paginated.total,
        "pages": paginated.pages,
        "tasks": [t.to_dict() for t in paginated.items]
    })


@task_bp.route('/', methods=['POST'])
@jwt_required()
def create_task():
    user_id = get_jwt_identity()
    data = request.get_json()
    if not data or 'title' not in data:
        abort(400, description="Missing 'title'")
    task = TaskService.create_task(user_id, data['title'], data.get('done', False))
    return jsonify(task.to_dict()), 201


@task_bp.route('/<int:task_id>', methods=['PUT'])
@jwt_required()
def update_task(task_id):
    user_id = get_jwt_identity()
    task = Task.query.filter_by(id=task_id, user_id=user_id).first_or_404()
    updated = TaskService.update_task(task, request.get_json())
    return jsonify(updated.to_dict())


@task_bp.route('/<int:task_id>', methods=['DELETE'])
@jwt_required()
def delete_task(task_id):
    user_id = get_jwt_identity()
    task = Task.query.filter_by(id=task_id, user_id=user_id).first_or_404()
    TaskService.delete_task(task)
    return '', 204
