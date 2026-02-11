from app import create_app, db
from config import DevelopmentConfig

app = create_app(DevelopmentConfig)


@app.shell_context_processor
def make_shell_context():
    return {"db": db}


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=8080)
