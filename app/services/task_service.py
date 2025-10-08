from app.models import Task
from app.extensions import db

class TaskService:
    @staticmethod
    def get_tasks(user_id, filters=None):
        query = Task.query.filter_by(user_id=user_id)

        if filters:
            if "done" in filters:
                query = query.filter_by(done=filters["done"])
            if "q" in filters:
                query = query.filter(Task.title.ilike(f"%{filters['q']}%"))

        sort = filters.get("sort", "id")
        desc = sort.startswith('-')
        field = sort[1:] if desc else sort
        if hasattr(Task, field):
            column = getattr(Task, field)
            query = query.order_by(column.desc() if desc else column.asc())

        return query

    @staticmethod
    def create_task(user_id, title, done=False):
        task = Task(title=title, done=done, user_id=user_id)
        db.session.add(task)
        db.session.commit()
        return task

    @staticmethod
    def update_task(task, data):
        task.title = data.get('title', task.title)
        task.done = data.get('done', task.done)
        db.session.commit()
        return task

    @staticmethod
    def delete_task(task):
        db.session.delete(task)
        db.session.commit()
