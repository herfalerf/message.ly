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
const { user } = require("../db");
const { markRead } = require("../models/message");

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/

router.get("/:id", async function (req, res, next) {
  try {
    let message = await Message.get(req.params.id);
    if (
      message.from_user.username === req.user.username ||
      message.to_user.username === req.user.username
    ) {
      return res.json({ message });
    } else {
      throw new ExpressError(
        "You do not have permission to access this page",
        401
      );
    }
  } catch (e) {
    return next(e);
  }
});

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/

router.post("/", async function (req, res, next) {
  try {
    let from_username = req.user.username;
    let { to_username, body } = req.body;
    let message = await Message.create({ from_username, to_username, body });
    return res.json({ message });
  } catch (e) {
    return next(e);
  }
});

/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

router.post("/:id/read", async function (req, res, next) {
  try {
    let message = await Message.get(req.params.id);
    if (message.to_user.username === req.user.username) {
      let read = await markRead(req.params.id);
      return res.json({ read });
    } else {
      throw new ExpressError(
        "You do not have permission to access this page",
        401
      );
    }
  } catch (e) {
    return next(e);
  }
});
module.exports = router;
