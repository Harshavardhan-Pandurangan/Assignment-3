"use strict";
/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
Object.defineProperty(exports, "__esModule", { value: true });
const path = require("path");
const datacache_1 = require("../data/datacache");
const challengeUtils = require("../lib/challengeUtils");
module.exports = function servePrivacyPolicyProof() {
    return (req, res) => {
        challengeUtils.solveIf(datacache_1.challenges.privacyPolicyProofChallenge, () => { return true; });
        res.sendFile(path.resolve('frontend/dist/frontend/assets/private/thank-you.jpg'));
    };
};
//# sourceMappingURL=privacyPolicyProof.js.map