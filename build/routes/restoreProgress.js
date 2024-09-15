"use strict";
/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
Object.defineProperty(exports, "__esModule", { value: true });
const Hashids = require("hashids/cjs");
const datacache_1 = require("../data/datacache");
const challengeUtils = require('../lib/challengeUtils');
module.exports.restoreProgress = function restoreProgress() {
    return ({ params }, res) => {
        const hashids = new Hashids('this is my salt', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');
        const continueCode = params.continueCode;
        const ids = hashids.decode(continueCode);
        if (challengeUtils.notSolved(datacache_1.challenges.continueCodeChallenge) && ids.includes(999)) {
            challengeUtils.solve(datacache_1.challenges.continueCodeChallenge);
            res.end();
        }
        else if (ids.length > 0) {
            for (const name in datacache_1.challenges) {
                if (Object.prototype.hasOwnProperty.call(datacache_1.challenges, name)) {
                    if (ids.includes(datacache_1.challenges[name].id)) {
                        challengeUtils.solve(datacache_1.challenges[name], true);
                    }
                }
            }
            res.json({ data: ids.length + ' solved challenges have been restored.' });
        }
        else {
            res.status(404).send('Invalid continue code.');
        }
    };
};
module.exports.restoreProgressFindIt = function restoreProgressFindIt() {
    return async ({ params }, res) => {
        const hashids = new Hashids('this is the salt for findIt challenges', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');
        const continueCodeFindIt = params.continueCode;
        const idsFindIt = hashids.decode(continueCodeFindIt);
        if (idsFindIt.length > 0) {
            for (const key in datacache_1.challenges) {
                if (Object.prototype.hasOwnProperty.call(datacache_1.challenges, key)) {
                    if (idsFindIt.includes(datacache_1.challenges[key].id)) {
                        await challengeUtils.solveFindIt(key, true);
                    }
                }
            }
            res.json({ data: idsFindIt.length + ' solved challenges have been restored.' });
        }
        else {
            res.status(404).send('Invalid continue code.');
        }
    };
};
module.exports.restoreProgressFixIt = function restoreProgressFixIt() {
    const hashids = new Hashids('yet another salt for the fixIt challenges', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');
    return async ({ params }, res) => {
        const continueCodeFixIt = params.continueCode;
        const idsFixIt = hashids.decode(continueCodeFixIt);
        if (idsFixIt.length > 0) {
            for (const key in datacache_1.challenges) {
                if (Object.prototype.hasOwnProperty.call(datacache_1.challenges, key)) {
                    if (idsFixIt.includes(datacache_1.challenges[key].id)) {
                        await challengeUtils.solveFixIt(key, true);
                    }
                }
            }
            res.json({ data: idsFixIt.length + ' solved challenges have been restored.' });
        }
        else {
            res.status(404).send('Invalid continue code.');
        }
    };
};
//# sourceMappingURL=restoreProgress.js.map