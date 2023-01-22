require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const ejs = require("ejs");
const fs = require("fs");
const path = require("path");
const nodemailer = require("nodemailer");
var admin = require("firebase-admin");
const uuid = require("uuid-v4");
const app = express();
const server = require("http").createServer(app);
const io = require("socket.io")(server);
const mailgun = require("mailgun-js")({
  apiKey: process.env.MAILGUN_API_KEY,
  domain: process.env.MAILGUN_DOMAIN,
});

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
// app.use("/uploads", express.static("uploads"));
app.use("/images", express.static(path.join(__dirname, "images")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, 'views'));

const { User, Report, Message, Chat } = require(path.join(__dirname, "schema.js"));
const emailContent = fs.readFileSync(
  path.join(__dirname, "views", "reset_password_email.ejs"),
  "utf8"
);

const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
};
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: `${process.env.FIREBASE_PROJECT_ID}.appspot.com`,
});

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.GMAIL,
    pass: process.env.GMAIL_PASSWORD,
  },
});
const saltRounds = 10;
const FIND_STRANGEE_PAGINATION = 30;
const FIND_STRANGEE_AGE_RADIUS = 10 * 365 * 86400 * 1000;
const MESSAGE_PAGINATION = 20;
const JWT_EXPIRATION_PERIOD = "30d";
const JWT_CHANGE_PERIOD = 7 * 86400000;
const JWT_APP_RESTART_PERIOD = 86400000 / 3;
const RESET_PASSWORD_LINK_EXPIRATION = "15m";
const GENDERS = ["Female", "Male", "Other"];
const statusData = {} /* To get user's status without querying DB */,
  usersFcmToken =
    {}; /* To get user's FCM token without querying DB each time (Stored after first DB query)*/

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, "uploads"));
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

mongoose.set("strictQuery", false);
mongoose.connect(process.env.MONGODB_URL, () => {
  console.log("Connected to MongoDB");
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

connection.once("open", () => {
  app.post("/check_registration", (req, res) => {
    req.body.email = req.body.email.toLowerCase();
    let exists = false;

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

  function uploadFile(file) {
    const metadata = {
      metadata: {
        // This line is very important. It's to create a download token.
        firebaseStorageDownloadTokens: uuid(),
      },
      contentType: file.mimetype,
      cacheControl: "public, max-age=31536000",
    };

    const filepath = path.join(__dirname, "uploads", file.filename);
    return admin
      .storage()
      .bucket()
      .upload(filepath, {
        destination: `uploads/${file.filename}`,
        // Support for HTTP requests made with `Accept-Encoding: gzip`
        gzip: true,
        metadata: metadata,
      });
  }

  app.post(
    "/profileImage",
    ensureAuthorized,
    upload.single("profileImage"),
    (req, res) => {
      uploadFile(req.file)
        .then(() => {
          res.status(200).send(true);
        })
        .catch((error) => {
          console.log("Upload error :::", error);
          res.status(200).send(false);
        });
    }
  );

  app.post(
    "/imageUpload",
    ensureAuthorized,
    upload.single("imageByUser"),
    (req, res) => {
      uploadFile(req.file)
        .then(() => {
          res.status(200).json(`uploads/${req.file.filename}`);
        })
        .catch((error) => {
          console.log("Upload error :::", error);
          res.status(500).json(`uploads/${req.file.filename}`);
        });
    }
  );

  app.post("/signup", upload.single("profileImage"), (req, res) => {
    req.body.email = req.body.email.toLowerCase();

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
          uploadFile(req.file)
            .then(() => {
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
                    fcmToken: req.body.fcmToken,
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
                          expiresIn: JWT_EXPIRATION_PERIOD,
                        }
                      );

                      const refreshToken = jwt.sign(
                        {
                          _id: result._id,
                          email: result.email,
                        },
                        process.env.JWT_REFRESH_KEY
                      );

                      return res.status(201).json({
                        message: "User created",
                        data: result,
                        token: token,
                        refreshToken: refreshToken,
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
            })
            .catch((error) => {
              console.log("Upload error :::", error);
              return res.status(500).json({
                error: "Failed to upload profile picture",
              });
            });
        }
      });
  });

  app.get("/uploads/:fileId", (req, res) => {
    res.redirect(
      process.env.FIREBASE_BASE_IMAGE_URL + req.params.fileId + "?alt=media"
    );
  });

  app.post("/login", (req, res) => {
    req.body.email = req.body.email.toLowerCase();

    User.find({ email: req.body.email })
      .exec()
      .then((users) => {
        if (users.length < 1) {
          return res.status(401).json({
            message: "Authentication failed",
          });
        }

        bcrypt.compare(req.body.password, users[0].password, (err, result) => {
          if (err || !result) {
            return res.status(401).json({
              message: "Authentication failed",
            });
          }
          const token = jwt.sign(
            {
              _id: users[0]._id,
              email: users[0].email,
            },
            process.env.JWT_KEY,
            {
              expiresIn: JWT_EXPIRATION_PERIOD,
            }
          );

          const refreshToken = jwt.sign(
            {
              _id: users[0]._id,
              email: users[0].email,
            },
            process.env.JWT_REFRESH_KEY
          );

          users[0].fcmToken = req.body.fcmToken;

          users[0].save((error, savedUser) => {
            if (error) {
              console.log("FCM TOken save error", error);
              return res.status(500).json({
                error: err,
              });
            } else {
              if (usersFcmToken[savedUser._id]) {
                delete usersFcmToken[savedUser._id];
              }

              savedUser.password = undefined;
              return res.status(200).json({
                message: "Authentication successful",
                data: savedUser,
                token: token,
                refreshToken: refreshToken,
              });
            }
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

  function filterStrangee(
    filterJson1,
    filterJson2,
    isFilterEnabled,
    req,
    res,
    callback
  ) {
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
                isFilterEnabled: isFilterEnabled,
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
              isFilterEnabled: isFilterEnabled,
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

          if (req.query.filterOn == "true") {
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
              true,
              req,
              res,
              null
            );
          } else {
            filterStrangee(
              JSON.parse(strangee_query),
              {
                country: req.body.country,
                birthday: {
                  $gte: parseInt(req.body.birthday) - FIND_STRANGEE_AGE_RADIUS,
                  $lte: parseInt(req.body.birthday) + FIND_STRANGEE_AGE_RADIUS,
                },
              },
              false,
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
                  false,
                  req,
                  res,
                  () => {
                    filterStrangee(null, null, false, req, res, null);
                  }
                );
              }
            );
          }
        } else {
          return res.status(401).json({
            error: "An error occured!",
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
            user.favourite.splice(
              user.favourite.indexOf(req.body.strangeeId),
              1
            );
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
          user.favourite.splice(
            user.favourite.indexOf(req.query.savedUserId),
            1
          );

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

  app.get("/amIBlocked", ensureAuthorized, (req, res) => {
    User.findOne({ _id: req.query.strangeeId })
      .exec()
      .then((user) => {
        if (user) {
          if (user.blocked.includes(req.user_unique_data._id)) {
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
    const myUserId = req.user_unique_data._id;
    const strangeeId = req.query._id;

    User.findOne({ _id: myUserId })
      .exec()
      .then((user) => {
        if (user) {
          if (req.query.blockedStatus == "true") {
            user.blocked.splice(user.blocked.indexOf(strangeeId), 1);
          } else {
            if (!user.blocked.includes(strangeeId)) {
              user.blocked.push(strangeeId);
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
              res.status(200).json({
                userId: strangeeId,
                error: false,
                blockedStatus: !blockedStatus,
              });

              let roomName = "";

              if (myUserId < strangeeId) {
                roomName = myUserId + strangeeId;
              } else {
                roomName = strangeeId + myUserId;
              }

              const blockData = {
                blockedBy: myUserId,
                blockedUser: strangeeId,
                status: !blockedStatus ? "blocked" : "unblocked",
              };

              console.log("Block data :::", blockData);

              return io
                .to(roomName)
                .emit("blockStatusChange", JSON.stringify(blockData));
            }
          });
        } else {
          return res.status(200).json({
            userId: strangeeId,
            error: true,
            blockedStatus: blockedStatus,
          });
        }
      })
      .catch((err) => {
        console.log(err);
        return res.status(200).json({
          userId: strangeeId,
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

  app.get("/message", ensureAuthorized, (req, res) => {
    Message.find({
      $or: [
        {
          userId: req.query.userId,
          strangeeId: req.query.strangeeId,
        },
        {
          userId: req.query.strangeeId,
          strangeeId: req.query.userId,
        },
      ],
      createdAt: {
        $lt:
          req.query.lastCreatedAt == "0" ? Date.now() : req.query.lastCreatedAt,
      },
    })
      .sort("-createdAt")
      .limit(MESSAGE_PAGINATION)
      .exec((error, messages) => {
        if (error) {
          console.log(error);
        } else {
          res.status(200).json(messages.reverse());
        }
      });
  });

  app.get("/chat", ensureAuthorized, async (req, res) => {
    User.findOne({ _id: req.user_unique_data._id }, async (err, user) => {
      if (err || !user) {
        console.log(err);
        res.status(500).json({
          error: err,
        });
      } else {
        req.favouriteArray = user.favourite;

        Chat.find({ userId: req.user_unique_data._id })
          .sort("-timestamp")
          .exec(async (error, chats) => {
            if (error) {
              console.log(error);
              res.status(500).json({
                error: error,
              });
            } else {
              const filteredChatArray = [];

              for (let i = 0; i < chats.length; i++) {
                chats[i].isOnline = statusData[chats[i].strangeeId] == "online";

                try {
                  const strangee = await User.findOne({
                    _id: chats[i].strangeeId,
                  }).exec();

                  if (strangee) {
                    chats[i].firstName = strangee.firstName;
                    chats[i].lastName = strangee.lastName;
                    chats[i].country = strangee.country;
                    chats[i].gender = strangee.gender;
                    chats[i].interestedIn = strangee.interestedIn;
                    chats[i].birthday = strangee.birthday;
                    chats[i].aboutMe = strangee.aboutMe;

                    filteredChatArray.push(chats[i]);
                  }
                } catch (e) {
                  console.log(e);
                }
              }

              res
                .status(200)
                .json(
                  filteredChatArray.map((element) => calcSaved(element, req))
                );
            }
          });
      }
    });
  });

  app.get("/terms_of_service", (req, res) => {
    res.render("terms_of_service", {
      appName: process.env.APP_NAME,
      emailAddress: process.env.EMAIL_ADDRESS,
    });
  });

  app.get("/privacy_policy", (req, res) => {
    res.render("privacy_policy", {
      appName: process.env.APP_NAME,
      emailAddress: process.env.EMAIL_ADDRESS,
    });
  });

  app.post("/forgotPassword", (req, res) => {
    console.log("Email for reset link: ", req.query.email);

    User.findOne({ email: req.query.email }, (err, user) => {
      if (err) {
        console.log(err);
        res.status(500).json({
          userFound: true,
          emailSent: false,
        });
      } else {
        if (user) {
          // Send reset link to req.query.email
          const secret = process.env.JWT_FORGOT_PASSWORD_KEY + user.password;
          const payload = {
            _id: user._id,
            email: user.email,
          };

          const token = jwt.sign(payload, secret, {
            expiresIn: RESET_PASSWORD_LINK_EXPIRATION,
          });
          const link =
            process.env.SERVER_URL + `/reset-password/${user._id}/${token}`;

          const emailTemplate = ejs.render(emailContent, {
            appName: process.env.APP_NAME,
            resetLink: link,
          });

          /* 
          // For gmail
          const mailOptions = {
            from: `${process.env.APP_NAME} <${process.env.GMAIL}>`, // Something like: Jane Doe <janedoe@gmail.com>
            to: req.query.email,
            subject: `Password reset link for ${process.env.APP_NAME}`,
            html: emailTemplate,
          };

          transporter.sendMail(mailOptions, (erro, info) => {
            if (erro) {
              console.log("Mail send error:", erro);
              res.status(200).json({
                userFound: true,
                emailSent: false,
              });
            } else {
              res.status(200).json({
                userFound: true,
                emailSent: true,
              });
            }
          }); */

          // For Mailgun
          const data = {
            from: `${process.env.APP_NAME} <${process.env.MAILGUN_EMAIL}>`,
            to: req.query.email,
            subject: `Password reset link for ${process.env.APP_NAME}`,
            html: emailTemplate
          };

          mailgun.messages().send(data, (erro, body) => {
            console.log("Body: ", body);
            if (erro) {
              console.log("Mail send error:", erro);
              res.status(200).json({
                userFound: true,
                emailSent: false,
              });
            } else {
              res.status(200).json({
                userFound: true,
                emailSent: true,
              });
            }
          });

        } else {
          res.status(200).json({
            userFound: false,
            emailSent: false,
          });
        }
      }
    });
  });

  app.get("/reset-password/:id/:token", (req, res) => {
    const { id, token } = req.params;

    User.findOne({ _id: id }, (err, user) => {
      if (err) {
        console.log(err);
        res.render("message", {
          message: "An unexpected error occured. Please try again!",
          success: false,
          appName: process.env.APP_NAME,
        });
      } else {
        if (user) {
          const secret = process.env.JWT_FORGOT_PASSWORD_KEY + user.password;

          try {
            const payload = jwt.verify(token, secret);
            res.render("reset-password", {
              email: user.email,
              appName: process.env.APP_NAME,
            });
          } catch (error) {
            console.log(error.message);
            res.render("message", {
              message:
                "The reset link is incorrect or has expired. Please try again!",
              success: false,
              appName: process.env.APP_NAME,
            });
          }
        } else {
          res.render("message", {
            message: "Invalid credentials. Please try again!",
            success: false,
            appName: process.env.APP_NAME,
          });
        }
      }
    });
  });

  app.post("/reset-password/:id/:token", (req, res) => {
    const { id, token } = req.params;
    const { password, password2 } = req.body;

    User.findOne({ _id: id }, (err, user) => {
      if (err) {
        console.log(err);
        res.render("message", {
          message: "An unexpected error occured. Please try again!",
          success: false,
          appName: process.env.APP_NAME,
        });
      } else {
        if (user) {
          const secret = process.env.JWT_FORGOT_PASSWORD_KEY + user.password;

          try {
            const payload = jwt.verify(token, secret);

            if (password.length < 6 || password != password2) {
              return res.render("message", {
                message: "Entered details are invalid. Please try again!",
                success: false,
                appName: process.env.APP_NAME,
              });
            } else {
              bcrypt.hash(password, saltRounds, (hashingError, hash) => {
                if (hashingError) {
                  return res.render("message", {
                    message: "An unexpected error occured. Please try again!",
                    success: false,
                    appName: process.env.APP_NAME,
                  });
                } else {
                  user.password = hash;
                  user.save((saveError, savedUser) => {
                    if (saveError) {
                      console.log(saveError);
                      return res.render("message", {
                        message:
                          "An unexpected error occured. Please try again!",
                        success: false,
                        appName: process.env.APP_NAME,
                      });
                    } else {
                      return res.render("message", {
                        message:
                          "Hurray! Your password has been successfully changed.",
                        success: true,
                        appName: process.env.APP_NAME,
                      });
                    }
                  });
                }
              });
            }
          } catch (error) {
            console.log(error.message);
            res.render("message", {
              message:
                "The reset link is incorrect or has expired. Please try again!",
              success: false,
              appName: process.env.APP_NAME,
            });
          }
        } else {
          res.render("message", {
            message: "Invalid credentials. Please try again!",
            success: false,
            appName: process.env.APP_NAME,
          });
        }
      }
    });
  });

  app.post("/refreshFcmToken", ensureAuthorized, (req, res) => {
    console.log("Query:", req.query);
    User.findOne({ _id: req.user_unique_data._id }, (err, user) => {
      if (err || !user) {
        res.status(200).send(false);
      } else {
        user.fcmToken = req.query.fcmToken;
        user.save((error, savedUser) => {
          if (error) {
            res.status(200).send(false);
          } else {
            res.status(200).send(true);

            if (usersFcmToken[req.user_unique_data._id]) {
              delete usersFcmToken[req.user_unique_data._id];
            }
          }
        });
      }
    });
  });

  app.post("/tokenCheck", (req, res) => {
    const decodedToken = jwt.decode(req.body.token);
    const payload = {
      _id: decodedToken._id,
      email: decodedToken.email,
    };

    const token = jwt.sign(payload, process.env.JWT_KEY, {
      expiresIn: JWT_EXPIRATION_PERIOD,
    });
    const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_KEY);

    jwt.verify(req.body.token, process.env.JWT_KEY, (err, jwt_data) => {
      if (err) {
        // check refresh token: if valid send new token and refresh token else send authorized = false
        jwt.verify(
          req.body.refreshToken,
          process.env.JWT_REFRESH_KEY,
          (error, refresh_jwt_data) => {
            if (error) {
              // check refresh token: if valid send new token and refresh token else send authorized = false
              res.status(200).json({
                authorized: false,
                restartOnTokenChange: true,
                token: req.body.token,
                refreshToken: req.body.refreshToken,
              });
            } else {
              // send new tokens
              res.status(200).json({
                authorized: true,
                restartOnTokenChange: true,
                token: token,
                refreshToken: refreshToken,
              });
            }
          }
        );
      } else {
        // check validity period: if validity > 7 days, send same tokens else send new rokens
        if (decodedToken.exp * 1000 < Date.now() + JWT_CHANGE_PERIOD) {
          res.status(200).json({
            authorized: true,
            restartOnTokenChange:
              decodedToken.exp * 1000 < Date.now() + JWT_APP_RESTART_PERIOD,
            token: token,
            refreshToken: refreshToken,
          });
        } else {
          res.status(200).json({
            authorized: true,
            restartOnTokenChange: false,
            token: req.body.token,
            refreshToken: req.body.refreshToken,
          });
        }
      }
    });
  });

  function sendChatNotification(data, userId, strangeeId, fcmToken) {
    const payload = {
      // "notification" is used when app is in background. Firebase displays this notification.
      notification: {
        title: "New message",
        body:
          data.message.type == "image"
            ? "Someone sent a photo."
            : data.message.text.slice(0, 100),
        image: process.env.FIREBASE_BASE_IMAGE_URL + userId + "?alt=media",
      },

      // "data" is used when app is in foreground. We need to display this with the help of data.
      data: {
        title: "New message",
        body:
          data.message.type == "image"
            ? "Someone sent a photo."
            : data.message.text.slice(0, 100),
        senderId: userId,
        receiverId: strangeeId,
        notificationType: "chat",
      },
    };

    admin
      .messaging()
      .sendToDevice(fcmToken, payload, {
        collapseKey: "stranzee_notif",
        priority: "high",
        timeToLive: 60 * 60 * 24 * 2 /* 2 days */,
      })
      .then((response) => {
        // notification sent successfully
      })
      .catch((error) => {
        console.log("Notification error", error);
      });
  }

  // For new JWT key:
  // console.log(require("crypto").randomBytes(64).toString("hex"));

  // Access token and refresh token implemented
  // Also need to implement refresh token in database
  // Tutorial: https://www.youtube.com/watch?v=mbsmsi7l3r4
  function ensureAuthorized(req, res, next) {
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

  io.on("connection", (socket) => {
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

        const timestamp = Date.now();
        data.message.timestamp = timestamp;
        data.message._id = new mongoose.Types.ObjectId().toHexString();
        io.to(roomName).emit("new message", [data.message]);

        const message = new Message(data.message);
        message.save();

        const myChat = {
          _id: userId + strangeeId,
          userId: userId,
          strangeeId: strangeeId,
          imageUrl: `uploads/${strangeeId}`,
          timestamp: timestamp,
          isRead: true,
          message:
            data.message.type == "image"
              ? "You sent a photo."
              : `You: ${data.message.text.slice(0, 100)}`,
        };

        const strangeeChat = {
          _id: strangeeId + userId,
          userId: strangeeId,
          strangeeId: userId,
          imageUrl: `uploads/${userId}`,
          timestamp: timestamp,
          isRead: false,
          message:
            data.message.type == "image"
              ? "Sent a photo."
              : data.message.text.slice(0, 100),
        };

        Chat.findOneAndUpdate({ _id: userId + strangeeId }, myChat, {
          upsert: true,
        }).exec();
        Chat.findOneAndUpdate({ _id: strangeeId + userId }, strangeeChat, {
          upsert: true,
        }).exec();

        /* io.to(strangeeId + "notification").emit("notification", {
          title: "New message",
          message:
            data.message.type == "image"
              ? "Sent a photo."
              : data.message.text.slice(0, 100),
          senderId: userId,
          receiverId: strangeeId,
          notificationType: "chat",
        }); */

        if (
          usersFcmToken[userId] &&
          Date.now() - usersFcmToken[userId]["time"] < 3600000 /* 1 hour */
        ) {
          sendChatNotification(
            data,
            userId,
            strangeeId,
            usersFcmToken[userId]["fcmToken"]
          );
        } else {
          User.findOne({ _id: strangeeId }, (err, user) => {
            if (err || !user) {
              console.log(err);
            } else {
              if (user.fcmToken) {
                usersFcmToken[userId] = {
                  fcmToken: user.fcmToken,
                  time: Date.now(),
                };

                sendChatNotification(data, userId, strangeeId, user.fcmToken);
              }
            }
          });
        }
      });
    });

    socket.on("message read", (read_data) => {
      const data = JSON.parse(read_data);
      const strangeeId = data.strangeeId.toString();

      jwtVerify(data.token, (userId) => {
        Chat.updateOne(
          {
            userId: userId,
            strangeeId: strangeeId,
          },
          {
            isRead: true,
          }
        ).exec();

        console.log(`Username : ${userId} is in chat with: ${strangeeId}`);
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
        } else if (data.purpose == "notification") {
          roomName = userId + "notification";
        }

        socket.join(roomName);
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
        } else if (data.purpose == "notification") {
          roomName = userId + "notification";
        }

        socket.leave(roomName);
        console.log(`Username : ${userId} left Room Name : ${roomName}`);
      });
    });
  });
});

process.on("uncaughtException", (err) => {
  console.log(err);
});

server.listen(process.env.PORT || 3000, () => {
  console.log("Server started at port 3000...");
});

/* app.listen(process.env.PORT || 3000, () => {
  console.log("Server started at port 3000...");
}); */
