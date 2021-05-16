const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");
const db = require("../db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
const {
  authenticateJWT,
  ensureLoggedIn,
  ensureCorrectUser,
} = require("../middleware/auth");
const User = require("../models/user");
const Message = require("../models/message");
const { updateLoginTimestamp } = require("../models/user");

/** get list of users.
 *
 * => {users: [{username, first_name, last_name, phone}, ...]}
 *
 **/

router.get("/", ensureLoggedIn, async function (req, res, next) {
  try {
    let users = await User.all();
    return res.json({ users });
  } catch (e) {
    return next(e);
  }
});

/** get detail of users.
 *
 * => {user: {username, first_name, last_name, phone, join_at, last_login_at}}
 *
 **/

router.get("/:username", ensureCorrectUser, async function (req, res, next) {
  try {
    let user = await User.get(req.params.username);
    return res.json({ user });
  } catch (e) {
    return next(e);
  }
});

/** get messages to user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 from_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/

router.get("/:username/to", ensureCorrectUser, async function (req, res, next) {
  try {
    let messages = await User.messagesTo(req.params.username);
    return res.json({ messages });
  } catch (e) {
    return next(e);
  }
});

/** get messages from user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 to_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/

router.get(
  "/:username/from",
  ensureCorrectUser,
  async function (req, res, next) {
    try {
      let messages = await User.messagesFrom(req.params.username);
      return res.json({ messages });
    } catch (e) {
      return next(e);
    }
  }
);

module.exports = router;
