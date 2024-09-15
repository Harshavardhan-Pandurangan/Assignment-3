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
module.exports = function saveLoginIp() {
    return (req, res, next) => {
        const loggedInUser = security.authenticatedUsers.from(req);
        if (loggedInUser !== undefined) {
            let lastLoginIp = req.headers['true-client-ip'];
            if (utils.isChallengeEnabled(challenges.httpHeaderXssChallenge)) {
                challengeUtils.solveIf(challenges.httpHeaderXssChallenge, () => { return lastLoginIp === '<iframe src="javascript:alert(`xss`)">'; });
            }
            else {
                lastLoginIp = security.sanitizeSecure(lastLoginIp);
            }
            if (lastLoginIp === undefined) {
                // @ts-expect-error FIXME types not matching
                lastLoginIp = utils.toSimpleIpAddress(req.socket.remoteAddress);
            }
            user_1.UserModel.findByPk(loggedInUser.data.id).then((user) => {
                user?.update({ lastLoginIp: lastLoginIp?.toString() }).then((user) => {
                    res.json(user);
                }).catch((error) => {
                    next(error);
                });
            }).catch((error) => {
                next(error);
            });
        }
        else {
            res.sendStatus(401);
        }
    };
};
//# sourceMappingURL=saveLoginIp.js.map