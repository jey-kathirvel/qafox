from flask import Blueprint, request
from flask_login import login_required
from marshmallow import Schema, fields, validate

catalog = Blueprint("catalog", __name__, url_prefix="/catalog")


class ItemSchema(Schema):
    title = fields.String(required=True, validate=validate.Length(min=1, max=80))
    publisher_id = fields.Integer(required=True)
    contact_email = fields.Email(required=True)


@catalog.route("/items", methods=["POST"])
@login_required
def create_item():
    title = request.form.get("title")
    publisher_id = request.form.get("publisher_id")
    payload = request.get_json(silent=True) or {}
    contact_email = payload.get("contact_email")
    return {"title": title, "publisher_id": publisher_id, "contact_email": contact_email}


@catalog.get("/items/<int:item_id>")
def read_item(item_id):
    q = request.args.get("q")
    return {"id": item_id, "q": q}
