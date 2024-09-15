"use strict";
/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
Object.defineProperty(exports, "__esModule", { value: true });
const challengeUtils = require("../lib/challengeUtils");
module.exports = function repeatNotification() {
    return ({ query }, res) => {
        const challengeName = decodeURIComponent(query.challenge);
        const challenge = challengeUtils.findChallengeByName(challengeName);
        if (challenge?.solved) {
            challengeUtils.sendNotification(challenge, true);
        }
        res.sendStatus(200);
    };
};
//# sourceMappingURL=repeatNotification.js.map