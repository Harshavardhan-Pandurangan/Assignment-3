"use strict";
/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
Object.defineProperty(exports, "__esModule", { value: true });
const Hashids = require("hashids/cjs");
const challenge_1 = require("../models/challenge");
const datacache_1 = require("../data/datacache");
const sequelize = require('sequelize');
const Op = sequelize.Op;
module.exports.continueCode = function continueCode() {
    const hashids = new Hashids('this is my salt', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');
    return (req, res) => {
        const ids = [];
        for (const name in datacache_1.challenges) {
            if (Object.prototype.hasOwnProperty.call(datacache_1.challenges, name)) {
                if (datacache_1.challenges[name].solved)
                    ids.push(datacache_1.challenges[name].id);
            }
        }
        const continueCode = ids.length > 0 ? hashids.encode(ids) : undefined;
        res.json({ continueCode });
    };
};
module.exports.continueCodeFindIt = function continueCodeFindIt() {
    const hashids = new Hashids('this is the salt for findIt challenges', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');
    return async (req, res) => {
        const ids = [];
        const challenges = await challenge_1.ChallengeModel.findAll({ where: { codingChallengeStatus: { [Op.gte]: 1 } } });
        for (const challenge of challenges) {
            ids.push(challenge.id);
        }
        const continueCode = ids.length > 0 ? hashids.encode(ids) : undefined;
        res.json({ continueCode });
    };
};
module.exports.continueCodeFixIt = function continueCodeFixIt() {
    const hashids = new Hashids('yet another salt for the fixIt challenges', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');
    return async (req, res) => {
        const ids = [];
        const challenges = await challenge_1.ChallengeModel.findAll({ where: { codingChallengeStatus: { [Op.gte]: 2 } } });
        for (const challenge of challenges) {
            ids.push(challenge.id);
        }
        const continueCode = ids.length > 0 ? hashids.encode(ids) : undefined;
        res.json({ continueCode });
    };
};
//# sourceMappingURL=continueCode.js.map