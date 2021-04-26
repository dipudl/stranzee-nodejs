require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const app = express();
const server = require("http").createServer(app);
const io = require("socket.io")(server);

app.use(express.json());
app.use("/uploads", express.static("uploads"));

const { User, Report, Message } = require(__dirname + "/schema.js");
const saltRounds = 10;
const FIND_STRANGEE_PAGINATION = 30;
const FIND_STRANGEE_AGE_RADIUS = 10 * 365 * 86400 * 1000;
const MESSAGE_PAGINATION = 20;
const GENDERS = ["Female", "Male", "Other"];
const statusData = {};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, __dirname + "/uploads/");
  },
  filename: (req, file, cb) => {
    // cb(null, file.originalname);
    let imageName = "";
    if (req.body._id) {
      if (req.user_unique_data._id) {
        imageName = req.user_unique_data._id; //+ "." + file.mimetype.split("/")[1];
        console.log("UserId provided... ProfileImage updated", imageName);
      } else {
        console.log(
          "Authentication error for profile image update...",
          req.body._id
        );
      }
    } else {
      let profileId = new mongoose.Types.ObjectId();
      imageName = profileId._id.toHexString(); //+ "." + file.mimetype.split("/")[1];
      req.profileId = profileId;

      console.log("UserId not provided... Image Uploaded");
      console.log("UserId not provided... _id", req.body);
      // console.log("UserId not provided... userId", req.body);
    }

    cb(null, imageName);
  },
});

const fileFilter = (req, file, cb) => {
  console.log("mime", file.mimetype);
  if (file.mimetype === "image/jpeg" || file.mimetype === "image/png") {
    cb(null, true);
  } else {
    // cb(null, false);
    cb(new Error("Wrong file type. Only jpeg or png file accepted."), false);
  }
};

const upload = multer({ storage: storage, fileFilter: fileFilter });

mongoose.connect(process.env.MONGODB_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
});
const connection = mongoose.connection;

/* app.get("/bro", (req, res) => {
  User.find({}).exec((err, users) => {
    if(err) {
      res.send("error");
    }else{
      "v".sub
      users.forEach(user => {
        if(!user.imageUrl.startsWith("uploads")) {
          // user.imageUrl = user.imageUrl.substring(0, user.imageUrl.length-1);
          // user.save();
          user.delete();
        }
      });
      res.send("success");
    }
  });
}); */

app.post("/check_registration", (req, res) => {
  let exists = false;
  console.log(req.body);

  User.findOne({ email: req.body.email })
    .exec()
    .then((user) => {
      if (user) {
        exists = true;
        console.log("User already exists.");
      }

      return res.status(200).json({
        user_not_exist: !exists,
      });
    });
});

app.post(
  "/profileImage",
  ensureAuthorized,
  upload.single("profileImage"),
  (req, res) => {
    console.log(req.file);
    console.log("ID:::", req.body._id);
    res.status(200).send(true);
  }
);

app.post(
  "/imageUpload",
  ensureAuthorized,
  upload.single("imageByUser"),
  (req, res) => {
    console.log(req.file);
    res.status(200).json(`uploads/${req.file.filename}`);
  }
);

app.post("/signup", upload.single("profileImage"), (req, res) => {
  console.log("signup", req.body);
  console.log("file", req.file);

  if (req.body.password.length < 6) {
    return res.status(500).json({
      error: "Password must be 6 characters or more",
    });
  }

  User.find({ email: req.body.email })
    .exec()
    .then((user) => {
      if (user.length >= 1) {
        return res.status(409).json({
          message: "Email already exists",
        });
      } else {
        bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
          if (err) {
            return res.status(500).json({
              error: err,
            });
          } else {
            console.log("profileImageName", req.profileImageName);

            const user = new User({
              _id: req.profileId,
              email: req.body.email,
              password: hash,
              firstName: req.body.firstName,
              lastName: req.body.lastName,
              imageUrl: `uploads/${req.file.filename}`,
              country: req.body.country,
              gender: req.body.gender,
              interestedIn: req.body.interestedIn.split(","),
              interestedInCaps: req.body.interestedIn
                .split(",")
                .map((interest) => interest.toUpperCase()),
              birthday: req.body.birthday,
              aboutMe: req.body.aboutMe,
            });

            user
              .save()
              .then((result) => {
                console.log(result);
                result.password = undefined;
                result.interestedInCaps = undefined;

                const token = jwt.sign(
                  {
                    _id: result._id,
                    email: result.email,
                  },
                  process.env.JWT_KEY,
                  {
                    // expiresIn: "90d",
                  }
                );

                return res.status(201).json({
                  message: "User created",
                  data: result,
                  token: token,
                });
              })
              .catch((err) => {
                console.log(err);
                res.status(500).json({
                  error: err,
                });
              });
          }
        });
      }
    });
});

app.post("/login", (req, res) => {
  console.log("Logging in...", req.body);
  User.find({ email: req.body.email })
    .exec()
    .then((users) => {
      if (users.length < 1) {
        return res.status(401).json({
          message: "Authentication failed",
        });
      }

      bcrypt.compare(req.body.password, users[0].password, (err, result) => {
        if (err) {
          return res.status(401).json({
            message: "Authentication failed",
          });
        }
        if (result) {
          users[0].password = undefined;

          const token = jwt.sign(
            {
              _id: users[0]._id,
              email: users[0].email,
            },
            process.env.JWT_KEY,
            {
              // expiresIn: "90d"
            }
          );

          return res.status(200).json({
            message: "Authentication successful",
            data: users[0],
            token: token,
          });
        }
        return res.status(401).json({
          message: "Authentication failed",
        });
      });
    })
    .catch((err) => {
      console.log(err);
      res.status(500).json({
        error: err,
      });
    });
});

function filterStrangee(filterJson1, filterJson2, req, res, callback) {
  User.find(filterJson1)
    .find(filterJson2)
    .find({ _id: { $ne: req.user_unique_data._id } })
    .find({
      createdAt: {
        $lt:
          req.query.lastCreatedAt == 0 ? Date.now() : req.query.lastCreatedAt,
      },
    })
    .select(
      "_id firstName lastName imageUrl country gender interestedIn birthday aboutMe createdAt"
    )
    .sort("-createdAt")
    .limit(FIND_STRANGEE_PAGINATION)
    .exec((err, users) => {
      if (err) {
        return res.status(500).json({
          error: err,
        });
      } else {
        let total_found = users.length;
        if (total_found < FIND_STRANGEE_PAGINATION) {
          if (callback) {
            callback();
          } else {
            return res.status(200).json({
              data: users.map((element) => calcSaved(element, req)),
              createdAt:
                users.length > 0 ? users[users.length - 1].createdAt : null,
            });
          }
        } else if (total_found >= FIND_STRANGEE_PAGINATION) {
          users.splice(
            FIND_STRANGEE_PAGINATION,
            total_found - FIND_STRANGEE_PAGINATION
          );

          return res.status(200).json({
            data: users.map((element) => calcSaved(element, req)),
            createdAt:
              users.length > 0 ? users[users.length - 1].createdAt : null,
          });
        }
      }
    });
}

function calcSaved(element, req) {
  const item = JSON.parse(JSON.stringify(element));
  item.saved = false;

  if (req.favouriteArray.includes(element._id)) {
    item.saved = true;
  }
  return item;
}

app.get("/strangee", ensureAuthorized, (req, res) => {
  console.log("Get strangee...");
  console.log("USER DATA: ", req.query.user);
  console.log("FILTER ON: ", req.query.filterOn);
  // req.query.lastCreatedAt = "2021-04-14T16:25:57.019Z";

  req.body = JSON.parse(req.query.user);

  let strangee_query = "{}";
  if (req.body.interestedIn.length > 0) {
    strangee_query = `{"$or": [`;
    req.body.interestedIn.forEach((interest, index) => {
      strangee_query += `{"interestedInCaps" : "${interest.toUpperCase()}"}`;
      if (index < req.body.interestedIn.length - 1) strangee_query += ",";
    });
    strangee_query += "]}";
  }

  User.findOne({ _id: req.user_unique_data._id })
    .exec()
    .then((user) => {
      if (user) {
        req.favouriteArray = user.favourite;
        console.log("Filter on type:", typeof req.query.filterOn);

        if (req.query.filterOn == "true") {
          console.log("Filter on");
          let otherFilters = "{";
          if (req.body.country != null && req.body.country != "Worldwide") {
            otherFilters += `"country": "${req.body.country}"`;

            if (GENDERS.includes(req.body.gender)) otherFilters += `,`;
          }

          if (GENDERS.includes(req.body.gender)) {
            otherFilters += `"gender": "${req.body.gender}"`;
          }

          otherFilters += "}";

          filterStrangee(
            JSON.parse(strangee_query),
            JSON.parse(otherFilters),
            req,
            res,
            null
          );
        } else {
          console.log("Filter off");
          filterStrangee(
            JSON.parse(strangee_query),
            {
              country: req.body.country,
              birthday: {
                $gte: parseInt(req.body.birthday) - FIND_STRANGEE_AGE_RADIUS,
                $lte: parseInt(req.body.birthday) + FIND_STRANGEE_AGE_RADIUS,
              },
            },
            req,
            res,
            () => {
              filterStrangee(
                {
                  birthday: {
                    $gte:
                      parseInt(req.body.birthday) - FIND_STRANGEE_AGE_RADIUS,
                    $lte:
                      parseInt(req.body.birthday) + FIND_STRANGEE_AGE_RADIUS,
                  },
                },
                null,
                req,
                res,
                () => {
                  filterStrangee(null, null, req, res, null);
                }
              );
            }
          );
        }
      } else {
        return res.status(401).json({
          error: err,
        });
      }
    });
});

app.post("/save", ensureAuthorized, (req, res) => {
  console.log(req.body);
  User.findOne({ _id: req.user_unique_data._id })
    .exec()
    .then((user) => {
      if (user) {
        if (req.body.currentSavedStatus) {
          user.favourite.splice(user.favourite.indexOf(req.body.strangeeId), 1);
          // user.favourite = user.favourite.filter(i => i !== req.body.strangeeId);
        } else {
          user.favourite.push(req.body.strangeeId);
        }
        user.save((err, savedUser) => {
          if (err) {
            return res.status(200).json({
              userId: req.body.strangeeId,
              error: true,
              saveStatus: req.body.currentSavedStatus,
            });
          } else {
            return res.status(200).json({
              userId: req.body.strangeeId,
              error: false,
              saveStatus: !req.body.currentSavedStatus,
            });
          }
        });
      } else {
        return res.status(200).json({
          userId: req.body.strangeeId,
          error: true,
          saveStatus: req.body.currentSavedStatus,
        });
      }
    })
    .catch((err) => {
      console.log(err);
      return res.status(200).json({
        userId: req.body.strangeeId,
        error: true,
        saveStatus: req.body.currentSavedStatus,
      });
    });
});

app.post("/editDetails", ensureAuthorized, (req, res) => {
  console.log("Edit details", req.body);

  User.findOne({ _id: req.user_unique_data._id })
    .exec()
    .then((user) => {
      if (user) {
        user.firstName = req.body.firstName;
        user.lastName = req.body.lastName;
        user.country = req.body.country;
        user.gender = req.body.gender;
        user.interestedIn = req.body.interestedIn;
        user.interestedInCaps = req.body.interestedIn.map((x) =>
          x.toUpperCase()
        );
        user.birthday = req.body.birthday;
        user.aboutMe = req.body.aboutMe;

        user.save((err, savedUser) => {
          if (err) {
            return res.status(500).json({
              error: err,
            });
          } else {
            return res.status(200).send(true);
          }
        });
      } else {
        return res.status(401).json({
          error: "Unauthorized request",
        });
      }
    })
    .catch((err) => {
      console.log(err);
      res.status(500).json({
        error: err,
      });
    });
});

app.post("/removeSaved", ensureAuthorized, (req, res) => {
  console.log("Edit details", req.query);

  User.findOne({ _id: req.user_unique_data._id })
    .exec()
    .then((user) => {
      if (user) {
        user.favourite.splice(user.favourite.indexOf(req.query.savedUserId), 1);

        user.save((err, savedUser) => {
          if (err) {
            return res.status(500).json({
              error: err,
            });
          } else {
            return res.status(200).send(true);
          }
        });
      } else {
        return res.status(401).json({
          error: "Unauthorized request",
        });
      }
    })
    .catch((err) => {
      console.log(err);
      res.status(500).json({
        error: err,
      });
    });
});

app.post("/removeWhoCheckedMe", ensureAuthorized, (req, res) => {
  console.log("Remove who checked me", req.query);

  User.findOne({ _id: req.user_unique_data._id })
    .exec()
    .then((user) => {
      if (user) {
        user.whoCheckedMe.splice(user.whoCheckedMe.indexOf(req.query._id), 1);

        user.save((err, savedUser) => {
          if (err) {
            return res.status(500).json({
              error: err,
            });
          } else {
            return res.status(200).send(true);
          }
        });
      } else {
        return res.status(401).json({
          error: "Unauthorized request",
        });
      }
    })
    .catch((err) => {
      console.log(err);
      res.status(500).json({
        error: err,
      });
    });
});

app.get("/saved", ensureAuthorized, (req, res) => {
  User.findOne({ _id: req.user_unique_data._id })
    .exec()
    .then((user) => {
      if (user) {
        const savedUsersId = user.favourite;

        User.find({ _id: { $in: savedUsersId } })
          .select(
            "_id firstName lastName imageUrl country gender interestedIn birthday aboutMe createdAt"
          )
          .exec((error, users) => {
            if (error) {
              res.status(500).json({
                error: error,
              });
            } else {
              res.status(200).send(
                users.map((element) => {
                  const item = JSON.parse(JSON.stringify(element));
                  item.saved = true;
                  return item;
                })
              );
            }
          });
      } else {
        return res.status(401).json({
          error: "Unauthorized request",
        });
      }
    })
    .catch((err) => {
      console.log(err);
      res.status(500).json({
        error: err,
      });
    });
});

app.get("/whoCheckedMe", ensureAuthorized, (req, res) => {
  User.findOne({ _id: req.user_unique_data._id })
    .exec()
    .then((user) => {
      if (user) {
        const favouriteIds = user.favourite;
        const whoCheckedMeIds = user.whoCheckedMe;

        User.find({ _id: { $in: whoCheckedMeIds } })
          .select(
            "_id firstName lastName imageUrl country gender interestedIn birthday aboutMe createdAt"
          )
          .exec((error, users) => {
            if (error) {
              res.status(500).json({
                error: error,
              });
            } else {
              res.status(200).send(
                users.map((element) => {
                  const item = JSON.parse(JSON.stringify(element));
                  item.saved = favouriteIds.includes(element._id);
                  return item;
                })
              );
            }
          });
      } else {
        return res.status(401).json({
          error: "Unauthorized request",
        });
      }
    })
    .catch((err) => {
      console.log(err);
      res.status(500).json({
        error: err,
      });
    });
});

app.get("/blocked", ensureAuthorized, (req, res) => {
  User.findOne({ _id: req.user_unique_data._id })
    .exec()
    .then((user) => {
      if (user) {
        if (user.blocked.includes(req.query._id)) {
          res.status(200).send(true);
        } else {
          res.status(200).send(false);
        }
      } else {
        return res.status(401).json({
          error: "Unauthorized request",
        });
      }
    })
    .catch((err) => {
      console.log(err);
      res.status(500).json({
        error: err,
      });
    });
});

app.post("/block", ensureAuthorized, (req, res) => {
  console.log(req.query);
  const blockedStatus = req.query.blockedStatus == "true";

  User.findOne({ _id: req.user_unique_data._id })
    .exec()
    .then((user) => {
      if (user) {
        if (req.query.blockedStatus == "true") {
          user.blocked.splice(user.blocked.indexOf(req.query._id), 1);
        } else {
          if (!user.blocked.includes(req.query._id)) {
            user.blocked.push(req.query._id);
          }
        }

        user.save((error, savedUser) => {
          if (error) {
            return res.status(200).json({
              userId: req.query._id,
              error: true,
              blockedStatus: blockedStatus,
            });
          } else {
            return res.status(200).json({
              userId: req.query._id,
              error: false,
              blockedStatus: !blockedStatus,
            });
          }
        });
      } else {
        return res.status(200).json({
          userId: req.query._id,
          error: true,
          blockedStatus: blockedStatus,
        });
      }
    })
    .catch((err) => {
      console.log(err);
      return res.status(200).json({
        userId: req.query._id,
        error: true,
        blockedStatus: blockedStatus,
      });
    });
});

app.post("/whoCheckedMe", ensureAuthorized, (req, res) => {
  console.log("Who checked me");
  console.log(req.query);

  User.findOne({ _id: req.user_unique_data._id }, (err, user) => {
    if (err) {
      res.status(500).send(false);
    } else {
      User.findOne({ _id: req.query._id }, (error, foundUser) => {
        if (error) {
          res.status(500).send(false);
        } else {
          if (!foundUser.whoCheckedMe.includes(req.user_unique_data._id)) {
            foundUser.whoCheckedMe.push(req.user_unique_data._id);
          }

          foundUser.save((e, savedUser) => {
            if (e) {
              res.status(500).send(false);
            } else {
              res.status(200).send(true);
            }
          });
        }
      });
    }
  });
});

app.post("/report", ensureAuthorized, (req, res) => {
  User.findOne({ _id: req.user_unique_data._id })
    .exec()
    .then((user) => {
      if (user) {
        const report = new Report({
          _id: new mongoose.Types.ObjectId(),
          reportedBy: req.user_unique_data._id,
          reportedUser: req.query.reportedUserId,
          message: req.query.message,
        });

        report.save((error, savedReport) => {
          if (error) {
            return res.status(200).send(false);
          } else {
            return res.status(200).send(true);
          }
        });
      } else {
        return res.status(200).send(false);
      }
    })
    .catch((err) => {
      console.log(err);
      res.status(200).send(false);
    });
});

app.post("/token_test", ensureAuthorized, (req, res) => {
  res.status(200).json({
    unique_data: req.user_unique_data,
  });
});

// Access token implemented
// Also need to implement refresh token to refresh access token without requiring user to log-out
// Tutorial: https://www.youtube.com/watch?v=mbsmsi7l3r4
function ensureAuthorized(req, res, next) {
  console.log("Checking authorization...");
  var bearerToken;
  var bearerHeader = req.headers["authorization"];
  if (typeof bearerHeader !== "undefined") {
    var bearerToken = bearerHeader.split(" ")[1];

    jwt.verify(bearerToken, process.env.JWT_KEY, (err, jwt_data) => {
      if (err) {
        console.log("Invalid authorization...", bearerToken);
        res.status(403).json({
          error: "Requested resource is forbidden",
        });
      } else {
        console.log("Valid authorization...", bearerToken);
        req.user_unique_data = jwt_data;
        next();
      }
    });
  } else {
    console.log("Invalid authorization...");
    res.status(403).json({
      error: "Requested resource is forbidden",
    });
  }
}

function jwtVerify(token, callback) {
  jwt.verify(token, process.env.JWT_KEY, (err, jwt_data) => {
    if (err) {
      console.log("JWT: Invalid authorization...", token);
    } else {
      callback(jwt_data._id.toString());
    }
  });
}

connection.once("open", () => {
  io.on("connection", (socket) => {
    console.log(`Connection : SocketId = ${socket.id}`);

    socket.on("status", (status_data) => {
      const data = JSON.parse(status_data);

      jwtVerify(data.token, (userId) => {
        statusData[userId] = data.status;
        // send status to data.userId room where some receivers are listening to this user's status
        io.to(`${userId}`).emit("statusChange", data.status);
      });
    });

    socket.on("message", (message_data) => {
      const data = JSON.parse(message_data);
      const strangeeId = data.message.strangeeId.toString();

      jwtVerify(data.token, (userId) => {
        let roomName = "";

        if (userId < strangeeId) {
          roomName = userId + strangeeId;
        } else {
          roomName = strangeeId + userId;
        }

        data.message.timestamp = Date.now();
        data.message._id = new mongoose.Types.ObjectId().toHexString();
        io.to(roomName).emit("new message", [data.message]);

        const message = new Message(data.message);
        message.save();

        console.log(data.message);
      });
    });

    socket.on("subscribe", (subscribe_data) => {
      const data = JSON.parse(subscribe_data);
      const strangeeId = data.strangeeId.toString();

      jwtVerify(data.token, (userId) => {
        let roomName = "";

        if (data.purpose == "status") {
          roomName = strangeeId;

          socket.join(roomName);
          io.to(roomName).emit(
            "statusChange",
            statusData[roomName] || "offline"
          );
        } else if (data.purpose == "chat") {
          if (userId < strangeeId) {
            roomName = userId + strangeeId;
          } else {
            roomName = strangeeId + userId;
          }

          // query database for previous chat data at roomName & then join room name
          Message.find({
            userId: userId,
            strangeeId: strangeeId,
          })
            .sort("createdAt")
            .limit(MESSAGE_PAGINATION)
            .exec((error, messages) => {
              socket.join(roomName);
              if (error) {
                console.log(error);
              } else {
                io.to(roomName).emit("older messages", messages);
              }
            });
        }

        console.log(`Username : ${userId} joined : ${subscribe_data}`);
      });
    });

    socket.on("unsubscribe", (unsubscribe_data) => {
      const data = JSON.parse(unsubscribe_data);
      const strangeeId = data.strangeeId.toString();

      jwtVerify(data.token, (userId) => {
        let roomName = "";

        if (data.purpose == "status") {
          roomName = strangeeId;
        } else if (data.purpose == "chat") {
          if (userId < strangeeId) {
            roomName = userId + strangeeId;
          } else {
            roomName = strangeeId + userId;
          }
        }

        socket.leave(roomName);
        console.log(`Username : ${userId} leaved Room Name : ${roomName}`);
      });
    });
  });
});

process.on("uncaughtException", (err) => {
  console.log(err);
});

server.listen(process.env.PORT | 3000, () => {
  console.log("Server started at port 3000...");
});

/* app.listen(process.env.PORT | 3000, () => {
  console.log("Server started at port 3000...");
}); */
