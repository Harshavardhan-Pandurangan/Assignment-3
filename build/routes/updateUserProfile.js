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
Object.defineProperty(exports, "__esModule", { value: true });
const user_1 = require("../models/user");
const challengeUtils = require("../lib/challengeUtils");
const utils = __importStar(require("../lib/utils"));
const security = require('../lib/insecurity');
const cache = require('../data/datacache');
const challenges = cache.challenges;
module.exports = function updateUserProfile() {
    return (req, res, next) => {
        const loggedInUser = security.authenticatedUsers.get(req.cookies.token);
        if (loggedInUser) {
            user_1.UserModel.findByPk(loggedInUser.data.id).then((user) => {
                if (user != null) {
                    challengeUtils.solveIf(challenges.csrfChallenge, () => {
                        return ((req.headers.origin?.includes('://htmledit.squarefree.com')) ??
                            (req.headers.referer?.includes('://htmledit.squarefree.com'))) &&
                            req.body.username !== user.username;
                    });
                    void user.update({ username: req.body.username }).then((savedUser) => {
                        // @ts-expect-error FIXME some properties missing in savedUser
                        savedUser = utils.queryResultToJson(savedUser);
                        const updatedToken = security.authorize(savedUser);
                        security.authenticatedUsers.put(updatedToken, savedUser);
                        res.cookie('token', updatedToken);
                        res.location(process.env.BASE_PATH + '/profile');
                        res.redirect(process.env.BASE_PATH + '/profile');
                    });
                }
            }).catch((error) => {
                next(error);
            });
        }
        else {
            next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
        }
    };
};
//# sourceMappingURL=updateUserProfile.js.map