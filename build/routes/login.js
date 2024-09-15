"use strict";
/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const models = require("../models/index");
const basket_1 = require("../models/basket");
const user_1 = require("../models/user");
const challengeUtils = require("../lib/challengeUtils");
const config_1 = __importDefault(require("config"));
const datacache_1 = require("../data/datacache");
const utils = __importStar(require("../lib/utils"));
const security = require("../lib/insecurity");
const users = require("../data/datacache").users;
// vuln-code-snippet start loginAdminChallenge loginBenderChallenge loginJimChallenge
module.exports = function login() {
    function afterLogin(user, res, next) {
        verifyPostLoginChallenges(user); // vuln-code-snippet hide-line
        basket_1.BasketModel.findOrCreate({ where: { UserId: user.data.id } })
            .then(([basket]) => {
            const token = security.authorize(user);
            user.bid = basket.id; // keep track of original basket
            security.authenticatedUsers.put(token, user);
            res.json({
                authentication: {
                    token,
                    bid: basket.id,
                    umail: user.data.email,
                },
            });
        })
            .catch((error) => {
            next(error);
        });
    }
    return (req, res, next) => {
        verifyPreLoginChallenges(req); // vuln-code-snippet hide-line
        // make sure the req.body.email is a string with no single quotes
        req.body.email = security.sanitizeSecure(req.body.email);
        req.body.password = security.sanitizeSecure(req.body.password);
        // for (const key in req.body) {
        //     if (req.body.hasOwnProperty(key)) {
        //         if (typeof req.body[key] === "string") {
        //             req.body[key] = req.body[key].replace(/'/g, "");
        //         }
        //     }
        // }
        console.log(req.body.email);
        models.sequelize
            .query(`SELECT * FROM Users WHERE email = '${req.body.email || ""}' AND password = '${security.hash(req.body.password || "")}' AND deletedAt IS NULL`, { model: user_1.UserModel, plain: true }) // vuln-code-snippet vuln-line loginAdminChallenge loginBenderChallenge loginJimChallenge
            .then((authenticatedUser) => {
            // vuln-code-snippet neutral-line loginAdminChallenge loginBenderChallenge loginJimChallenge
            const user = utils.queryResultToJson(authenticatedUser);
            if (user.data?.id && user.data.totpSecret !== "") {
                res.status(401).json({
                    status: "totp_token_required",
                    data: {
                        tmpToken: security.authorize({
                            userId: user.data.id,
                            type: "password_valid_needs_second_factor_token",
                        }),
                    },
                });
            }
            else if (user.data?.id) {
                // @ts-expect-error FIXME some properties missing in user - vuln-code-snippet hide-line
                afterLogin(user, res, next);
            }
            else {
                res.status(401).send(res.__("Invalid email or password."));
            }
        })
            .catch((error) => {
            next(error);
        });
    };
    // vuln-code-snippet end loginAdminChallenge loginBenderChallenge loginJimChallenge
    function verifyPreLoginChallenges(req) {
        challengeUtils.solveIf(datacache_1.challenges.weakPasswordChallenge, () => {
            return (req.body.email ===
                "admin@" + config_1.default.get("application.domain") &&
                req.body.password === "admin123");
        });
        challengeUtils.solveIf(datacache_1.challenges.loginSupportChallenge, () => {
            return (req.body.email ===
                "support@" + config_1.default.get("application.domain") &&
                req.body.password === "J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P");
        });
        challengeUtils.solveIf(datacache_1.challenges.loginRapperChallenge, () => {
            return (req.body.email ===
                "mc.safesearch@" +
                    config_1.default.get("application.domain") &&
                req.body.password === "Mr. N00dles");
        });
        challengeUtils.solveIf(datacache_1.challenges.loginAmyChallenge, () => {
            return (req.body.email ===
                "amy@" + config_1.default.get("application.domain") &&
                req.body.password === "K1f.....................");
        });
        challengeUtils.solveIf(datacache_1.challenges.dlpPasswordSprayingChallenge, () => {
            return (req.body.email ===
                "J12934@" + config_1.default.get("application.domain") &&
                req.body.password === "0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB");
        });
        challengeUtils.solveIf(datacache_1.challenges.oauthUserPasswordChallenge, () => {
            return (req.body.email === "bjoern.kimminich@gmail.com" &&
                req.body.password === "bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=");
        });
    }
    function verifyPostLoginChallenges(user) {
        challengeUtils.solveIf(datacache_1.challenges.loginAdminChallenge, () => {
            return user.data.id === users.admin.id;
        });
        challengeUtils.solveIf(datacache_1.challenges.loginJimChallenge, () => {
            return user.data.id === users.jim.id;
        });
        challengeUtils.solveIf(datacache_1.challenges.loginBenderChallenge, () => {
            return user.data.id === users.bender.id;
        });
        challengeUtils.solveIf(datacache_1.challenges.ghostLoginChallenge, () => {
            return user.data.id === users.chris.id;
        });
        if (challengeUtils.notSolved(datacache_1.challenges.ephemeralAccountantChallenge) &&
            user.data.email ===
                "acc0unt4nt@" + config_1.default.get("application.domain") &&
            user.data.role === "accounting") {
            user_1.UserModel.count({
                where: {
                    email: "acc0unt4nt@" +
                        config_1.default.get("application.domain"),
                },
            })
                .then((count) => {
                if (count === 0) {
                    challengeUtils.solve(datacache_1.challenges.ephemeralAccountantChallenge);
                }
            })
                .catch(() => {
                throw new Error("Unable to verify challenges! Try again");
            });
        }
    }
};
//# sourceMappingURL=login.js.map