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
const fs = require("fs");
const datacache_1 = require("../data/datacache");
const user_1 = require("../models/user");
const challengeUtils = require("../lib/challengeUtils");
const config_1 = __importDefault(require("config"));
const utils = __importStar(require("../lib/utils"));
const html_entities_1 = require("html-entities");
const security = require('../lib/insecurity');
const pug = require('pug');
const themes = require('../views/themes/themes').themes;
const entities = new html_entities_1.AllHtmlEntities();
module.exports = function getUserProfile() {
    return (req, res, next) => {
        fs.readFile('views/userProfile.pug', function (err, buf) {
            if (err != null)
                throw err;
            const loggedInUser = security.authenticatedUsers.get(req.cookies.token);
            if (loggedInUser) {
                user_1.UserModel.findByPk(loggedInUser.data.id).then((user) => {
                    let template = buf.toString();
                    let username = user?.username;
                    if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(datacache_1.challenges.usernameXssChallenge)) {
                        req.app.locals.abused_ssti_bug = true;
                        const code = username?.substring(2, username.length - 1);
                        try {
                            if (!code) {
                                throw new Error('Username is null');
                            }
                            username = eval(code); // eslint-disable-line no-eval
                        }
                        catch (err) {
                            username = '\\' + username;
                        }
                    }
                    else {
                        username = '\\' + username;
                    }
                    const theme = themes[config_1.default.get('application.theme')];
                    if (username) {
                        template = template.replace(/_username_/g, username);
                    }
                    template = template.replace(/_emailHash_/g, security.hash(user?.email));
                    template = template.replace(/_title_/g, entities.encode(config_1.default.get('application.name')));
                    template = template.replace(/_favicon_/g, favicon());
                    template = template.replace(/_bgColor_/g, theme.bgColor);
                    template = template.replace(/_textColor_/g, theme.textColor);
                    template = template.replace(/_navColor_/g, theme.navColor);
                    template = template.replace(/_primLight_/g, theme.primLight);
                    template = template.replace(/_primDark_/g, theme.primDark);
                    template = template.replace(/_logo_/g, utils.extractFilename(config_1.default.get('application.logo')));
                    const fn = pug.compile(template);
                    const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval' https://code.getmdl.io http://ajax.googleapis.com`;
                    // @ts-expect-error FIXME type issue with string vs. undefined for username
                    challengeUtils.solveIf(datacache_1.challenges.usernameXssChallenge, () => { return user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>'); });
                    res.set({
                        'Content-Security-Policy': CSP
                    });
                    res.send(fn(user));
                }).catch((error) => {
                    next(error);
                });
            }
            else {
                next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
            }
        });
    };
    function favicon() {
        return utils.extractFilename(config_1.default.get('application.favicon'));
    }
};
//# sourceMappingURL=userProfile.js.map