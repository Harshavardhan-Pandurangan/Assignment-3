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
const utils = require("../lib/utils");
const challengeUtils = require("../lib/challengeUtils");
const db = __importStar(require("../data/mongodb"));
const datacache_1 = require("../data/datacache");
const security = require('../lib/insecurity');
// Blocking sleep function as in native MongoDB
// @ts-expect-error FIXME Type safety broken for global object
global.sleep = (time) => {
    // Ensure that users don't accidentally dos their servers for too long
    if (time > 2000) {
        time = 2000;
    }
    const stop = new Date().getTime();
    while (new Date().getTime() < stop + time) {
        ;
    }
};
module.exports = function productReviews() {
    return (req, res, next) => {
        const id = !utils.isChallengeEnabled(datacache_1.challenges.noSqlCommandChallenge) ? Number(req.params.id) : req.params.id;
        // Measure how long the query takes, to check if there was a nosql dos attack
        const t0 = new Date().getTime();
        db.reviewsCollection.find({ $where: 'this.product == ' + id }).then((reviews) => {
            const t1 = new Date().getTime();
            challengeUtils.solveIf(datacache_1.challenges.noSqlCommandChallenge, () => { return (t1 - t0) > 2000; });
            const user = security.authenticatedUsers.from(req);
            for (let i = 0; i < reviews.length; i++) {
                if (user === undefined || reviews[i].likedBy.includes(user.data.email)) {
                    reviews[i].liked = true;
                }
            }
            res.json(utils.queryResultToJson(reviews));
        }, () => {
            res.status(400).json({ error: 'Wrong Params' });
        });
    };
};
//# sourceMappingURL=showProductReviews.js.map