const db = require("../db");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
const ExpressError = require("../expressError");
const bcrypt = require("bcrypt");
// const { user } = require("../db");

/** User class for message.ly */

/** User of the site. */

class User {
  constructor(username, password, first_name, last_name, phone) {
    this.username = username;
    this.password = password;
    this.first_name = first_name;
    this.last_name = last_name;
    this.phone = phone;
  }
  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    let user = new User(username, password, first_name, last_name, phone);
    const hashedPassword = await bcrypt.hash(user.password, BCRYPT_WORK_FACTOR);
    user.password = hashedPassword;

    const results = await db.query(
      `
      INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
      VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
      RETURNING username, password, first_name, last_name, phone`,
      [
        user.username,
        user.password,
        user.first_name,
        user.last_name,
        user.phone,
      ]
    );
    return results.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const results = await db.query(
      `SELECT username, password
    FROM users
    WHERE username = $1`,
      [username]
    );
    const user = results.rows[0];
    if (user) {
      return (await bcrypt.compare(password, user.password)) ? true : false;
    }
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const results = await db.query(
      `UPDATE users 
    SET last_login_at = current_timestamp
    WHERE username = $1
    RETURNING username, last_login_at`,
      [username]
    );
    const user = results.rows[0];
    if (user) {
      return user;
    } else {
      return new ExpressError("User cannot be found", 404);
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone
      FROM users`
    );
    return results.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at
      FROM users
      WHERE username = $1
      `,
      [username]
    );
    return results.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const results = await db.query(
      `SELECT m.id, 
              m.to_username, 
              t.first_name, 
              t.last_name,
              t.phone, 
              m.body, 
              m.sent_at, 
              m.read_at 
      FROM messages AS m
      JOIN users AS t ON m.to_username = t.username
      WHERE m.from_username = $1
      `,
      [username]
    );
    return results.rows.map((m) => ({
      id: m.id,
      to_user: {
        username: m.to_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone,
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at,
    }));
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {id, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const results = await db.query(
      `SELECT m.id,
              m.from_username,
              f.first_name,
              f.last_name,
              f.phone,
              m.body,
              m.sent_at,
              m.read_at
              FROM messages AS m
              JOIN users AS f ON m.from_username = f.username
              WHERE m.to_username = $1`,
      [username]
    );
    return results.rows.map((m) => ({
      id: m.id,
      from_user: {
        username: m.from_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone,
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at,
    }));
  }
}

module.exports = User;
