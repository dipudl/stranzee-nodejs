const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    _id: mongoose.Schema.Types.ObjectId,
    email: {
      type: String,
      unique: true,
      required: true,
      match: /^[\w-_\.+]*[\w-_\.]\@([\w]+\.)+[\w]+[\w]$/,
    },
    password: { type: String, required: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    imageUrl: { type: String, required: true },
    /* Recommendation criterias */
    // XX If country matches or neighbouring country
    // LATER : 30% of same gender and 70% different gender
    // XX If one or more interestedIn matches
    // XX If birthday is +- 10 years
    // LATER : If about me matches 30% or more(should be at least 100 characters long) / contains interestedIn (only 5 or more characters interestedIn considered)
    country: { type: String, required: true },
    gender: { type: String, required: true },
    interestedIn: { type: [String], required: true },
    interestedInCaps: { type: [String], required: true },
    birthday: { type: Number, required: true },
    aboutMe: { type: String, required: true },
    favourite: { type: [String], default: [] },
    blocked: { type: [String], default: [] },
    whoCheckedMe: { type: [String], default: [] },
  },
  { timestamps: true }
);

const reportSchema = new mongoose.Schema(
  {
    _id: mongoose.Schema.Types.ObjectId,
    reportedBy: { type: String, required: true },
    reportedUser: { type: String, required: true },
    message: { type: String, required: true },
  },
  { timestamps: true }
);

const messageSchema = new mongoose.Schema(
  {
    _id: mongoose.Schema.Types.ObjectId,
    userId: { type: String, required: true },
    strangeeId: { type: String, required: true },
    text: String,
    type: { type: String, required: true },
    imageUrl: String,
    timestamp: { type: Number, required: true },
  },
  { timestamps: true }
);

const chatSchema = new mongoose.Schema(
  {
    _id: { type: String, required: true },
    userId: { type: String, required: true },
    strangeeId: { type: String, required: true },
    imageUrl: { type: String, required: true },
    timestamp: { type: Number, required: true },
    message: { type: String, required: true },
    isRead: { type: Boolean, required: true, default: false},

    // not required, fetched when needed (for fresh data)
    firstName: { type: String, required: false },
    lastName: { type: String, required: false },
    country: { type: String, required: false },
    gender: { type: String, required: false },
    interestedIn: { type: [String], required: false },
    birthday: { type: Number, required: false },
    aboutMe: { type: String, required: false },
    isOnline: { type: Boolean, required: false}
  },
  { timestamps: true }
);

module.exports.User = mongoose.model("User", userSchema);
module.exports.Report = mongoose.model("Report", reportSchema);
module.exports.Message = mongoose.model("Message", messageSchema);
module.exports.Chat = mongoose.model("Chat", chatSchema);