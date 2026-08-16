const express = require("express");

const app = express();
const api = express.Router();
const catalog = express.Router();

app.use("/api", api);
api.use("/v1", catalog);

catalog.get("/items/:id", function (req, res) {
  res.json({ id: req.params.id });
});

module.exports = app;
