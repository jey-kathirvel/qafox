from fastapi import FastAPI

app = FastAPI()


@app.get("/must-not-appear")
def hidden():
    return {}
