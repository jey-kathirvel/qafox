const mongoose = require("mongoose");

const ItemSchema = new mongoose.Schema({
  title: { type: String, required: true },
  publisher: { type: mongoose.Schema.Types.ObjectId, ref: "Publisher" },
  contact_email: { type: String, required: true },
});

module.exports = mongoose.model("Item", ItemSchema);
