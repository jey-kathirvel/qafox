const express = require("express");
const { z } = require("zod");
const jwt = require("jsonwebtoken");

const app = express();
const api = express.Router();
const catalog = express.Router();

app.use("/api", api);
api.use("/v1", catalog);

const ItemInput = z.object({
  title: z.string().min(2).max(80),
  contact_email: z.string().email(),
  publisher_id: z.number().min(1),
});

catalog.get("/items/:id", function (req, res) {
  const id = req.params.id;
  const q = req.query.q;
  res.json({ id: id, q: q });
});

catalog.post("/items", jwt, function (req, res) {
  const title = req.body.title;
  const email = req.body.contact_email;
  res.json({ title, email });
});

module.exports = app;
