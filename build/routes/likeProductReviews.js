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
const challengeUtils = require("../lib/challengeUtils");
const db = __importStar(require("../data/mongodb"));
const datacache_1 = require("../data/datacache");
const security = require('../lib/insecurity');
module.exports = function productReviews() {
    return (req, res, next) => {
        const id = req.body.id;
        const user = security.authenticatedUsers.from(req);
        db.reviewsCollection.findOne({ _id: id }).then((review) => {
            if (!review) {
                res.status(404).json({ error: 'Not found' });
            }
            else {
                const likedBy = review.likedBy;
                if (!likedBy.includes(user.data.email)) {
                    db.reviewsCollection.update({ _id: id }, { $inc: { likesCount: 1 } }).then(() => {
                        // Artificial wait for timing attack challenge
                        setTimeout(function () {
                            db.reviewsCollection.findOne({ _id: id }).then((review) => {
                                const likedBy = review.likedBy;
                                likedBy.push(user.data.email);
                                let count = 0;
                                for (let i = 0; i < likedBy.length; i++) {
                                    if (likedBy[i] === user.data.email) {
                                        count++;
                                    }
                                }
                                challengeUtils.solveIf(datacache_1.challenges.timingAttackChallenge, () => { return count > 2; });
                                db.reviewsCollection.update({ _id: id }, { $set: { likedBy } }).then((result) => {
                                    res.json(result);
                                }, (err) => {
                                    res.status(500).json(err);
                                });
                            }, () => {
                                res.status(400).json({ error: 'Wrong Params' });
                            });
                        }, 150);
                    }, (err) => {
                        res.status(500).json(err);
                    });
                }
                else {
                    res.status(403).json({ error: 'Not allowed' });
                }
            }
        }, () => {
            res.status(400).json({ error: 'Wrong Params' });
        });
    };
};
//# sourceMappingURL=likeProductReviews.js.map