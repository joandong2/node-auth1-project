const express = require("express");
const bcrypt = require("bcryptjs");
const Users = require("./users-model");
//const restrict = require("../middleware/restrict");

const router = express.Router();

router.post("/api/register", async (req, res, next) => {
    try {
        const { username, password } = req.body;
        const user = await Users.findBy({ username }).first();

        if (user) {
            return res.status(409).json({
                message: "Username is already taken",
            });
        }

        const newUser = await Users.add({
            username,
            // hash the password with a time complexity of "14"
            password: await bcrypt.hash(password, 14),
        });

        res.status(201).json(newUser);
    } catch (err) {
        next(err);
    }
});

router.post("/api/login", async (req, res, next) => {
    try {
        const { username, password } = req.body;
        const user = await Users.findBy({ username }).first();

        if (!user) {
            return res.status(401).json({
                message: "Invalid Credentials",
            });
        }

        // hash the password again and see if it matches what we have in the database
        const passwordValid = await bcrypt.compare(password, user.password);

        if (!passwordValid) {
            return res.status(401).json({
                message: "Invalid Credentials",
            });
        }

        // generate a new session for this user,
        // and sends back a session ID
        req.session.user = user;

        res.json({
            message: `Welcome ${user.username}!`,
        });
    } catch (err) {
        next(err);
    }
});

router.get("/api/users", async (req, res, next) => {
    try {
        if (!req.session || !req.session.user) {
            return res
                .status(401)
                .json({ error: "No session available, Please login" });
        }

        res.json(await Users.find());
    } catch (err) {
        next(err);
    }
});

module.exports = router;
