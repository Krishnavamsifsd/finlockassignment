import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import UserModel from "./models/user.js";
import sqlite3 from "sqlite3";
import dotenv from "dotenv";
import session from "express-session";
import SqliteStore from "connect-sqlite3";
import Cors from "cors";
dotenv.config();

const app = express();

app.use(
  express.urlencoded({
    extended: true,
  })
);

app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
const corsOptions = {
  origin: true,
  credentials: true,
};
app.use(Cors(corsOptions));

const db = new sqlite3.Database(":memory:");
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (email TEXT, password TEXT)");
});

app.use(
  session({
    secret: "shadow329",
    cookie: {},
    resave: false,
    saveUninitialized: false,
    store: new SqliteStore({
      db,
      table: "sessions",
    }),
  })
);

app.post("/", (req, res) => {
  req.session.user = req.body.email;
  console.log(req.body);
  db.get(
    `SELECT * FROM users WHERE email = ?`,
    req.body.email,
    (err, result) => {
      if (err) {
        res.status(500).send(err);
      }
      if (!result) {
        console.log(result);
        db.run(
          `INSERT INTO users (email, password) VALUES (?, ?)`,
          req.body.email,
          req.body.password,
          (err) => {
            if (err) {
              console.log(err);
              res.status(500).send(err);
            } else {
              const user = {
                email: req.body.email,
                password: req.body.password,
              };
              const token = jwt.sign(user, process.env.MY_SECRET, {
                expiresIn: "60s",
              });
              console.log("This is token ", token);
              res.cookie("token", token, {
                httpOnly: false,
              });
              res.status(201).send("Successfully created");
            }
          }
        );
      }
      if (result) {
        if (result.password !== req.body.password) {
          result.status(403).send("Invalid Password");
        } else {
          const user = { email: req.body.email, password: req.body.password };
          const token = jwt.sign(user, process.env.MY_SECRET, {
            expiresIn: "60s",
          });
          res.cookie("token", token, {
            httpOnly: false,
          });
        }
      }
    }
  );
});

app.get("/", (req, res) => {
  console.log("This is cookies ", req.cookies);
  jwt.verify(req.cookies.token, process.env.MY_SECRET, (err, result) => {
    if (err) {
      res.status(404).send("Cannot find the credentials");
    } else {
      console.log("This is email ", result.email);
      res.status(200).send(result.email);
    }
  });
});

const port = process.env.PORT || 9000;
app.listen(port, () => {
  console.log("Localhost listening on", port);
});
