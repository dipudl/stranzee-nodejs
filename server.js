require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, __dirname + "/uploads/");
  },
  filename: (req, file, cb) => {
    // cb(null, file.originalname);
    let profileId = new mongoose.Types.ObjectId();
    let imageName =
      profileId._id.toHexString() + "." + file.mimetype.split("/")[1];
    req.profileId = profileId;
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

const app = express();
app.use(express.json());
app.use("/uploads", express.static("uploads"));
const { User, Strangee } = require(__dirname + "/schema.js");

const saltRounds = 10;
const FIND_STRANGEE_PAGINATION = 30;
const FIND_STRANGEE_AGE_RADIUS = 10 * 365 * 86400 * 1000;

mongoose.connect("mongodb://localhost:27017/strangeeDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
});

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
                    expiresIn: "90d",
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
              expiresIn: "90d",
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
    .select(
      "_id firstName lastName imageUrl country gender interestedIn birthday aboutMe"
    )
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
            console.log("USERS:::", users);
            return res.status(200).json({
              data: users.map((element) => calcSaved(element, req)),
            });
          }
        } else if (total_found >= FIND_STRANGEE_PAGINATION) {
          users.splice(
            FIND_STRANGEE_PAGINATION,
            total_found - FIND_STRANGEE_PAGINATION
          );

          return res.status(200).json({
            data: users.map((element) => calcSaved(element, req)),
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

  req.body = JSON.parse(req.query.user);

  let strangee_query = `{"$or": [`;
  req.body.interestedIn.forEach((interest, index) => {
    strangee_query += `{"interestedInCaps" : "${interest.toUpperCase()}"}`;
    if (index < req.body.interestedIn.length - 1) strangee_query += ",";
  });
  strangee_query += "]}";

  User.findOne({ _id: req.user_unique_data._id })
    .exec()
    .then((user) => {
      if (user) {
        req.favouriteArray = user.favourite;

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
                  $gte: parseInt(req.body.birthday) - FIND_STRANGEE_AGE_RADIUS,
                  $lte: parseInt(req.body.birthday) + FIND_STRANGEE_AGE_RADIUS,
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
      } else {
        return res.status(401).json({
          error: err,
        });
      }
    });
});

app.post("/save", ensureAuthorized, (req, res) => {
  User.findOne({ _id: req.user_unique_data._id })
    .exec()
    .then((user) => {
      if (user) {
        if (req.body.currentSavedStatus) {
          user.favourite = user.favourite.splice(
            user.favourite.indexOf(req.body.strangeeId),
            1
          );
          // user.favourite = user.favourite.filter(i => i !== req.body.strangeeId);
        } else {
          user.favourite.push(req.body.strangeeId);
        }
        user.save((err, savedUser) => {
          if (err) {
            return res.status(401).json({
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
        return res.status(401).json({
          userId: req.body.strangeeId,
          error: true,
          saveStatus: req.body.currentSavedStatus,
        });
      }
    });
});

app.post("/test", ensureAuthorized, (req, res) => {
  res.status(200).json({
    unique_data: req.user_unique_data,
  });
});

// Access token implemented
// Also need to implement refresh token to refresh access token without requiring user to log-out
// Tutorial: https://www.youtube.com/watch?v=mbsmsi7l3r4
function ensureAuthorized(req, res, next) {
  var bearerToken;
  var bearerHeader = req.headers["authorization"];
  if (typeof bearerHeader !== "undefined") {
    var bearerToken = bearerHeader.split(" ")[1];

    jwt.verify(bearerToken, process.env.JWT_KEY, (err, jwt_data) => {
      if (err) {
        res.status(403).json({
          error: "Requested resource is forbidden",
        });
      }

      req.user_unique_data = jwt_data;
      next();
    });
  } else {
    res.status(403).json({
      error: "Requested resource is forbidden",
    });
  }
}

process.on("uncaughtException", (err) => {
  console.log(err);
});

app.listen(process.env.PORT | 3000, () => {
  console.log("Server started at port 3000...");
});
