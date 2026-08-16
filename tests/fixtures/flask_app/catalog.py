from flask import Blueprint, request
from flask_login import login_required

catalog = Blueprint("catalog", __name__, url_prefix="/catalog")


@catalog.route("/items", methods=["POST"])
@login_required
def create_item():
    title = request.form.get("title")
    publisher_id = request.form.get("publisher_id")
    return {"title": title, "publisher_id": publisher_id}


@catalog.get("/items/<int:item_id>")
def read_item(item_id):
    return {"id": item_id}
