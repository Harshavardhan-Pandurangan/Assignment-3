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
exports.notify = void 0;
const os_1 = __importDefault(require("os"));
const util_1 = require("util");
const request_1 = __importDefault(require("request"));
const logger_1 = __importDefault(require("./logger"));
const config_1 = __importDefault(require("config"));
const safe_1 = __importDefault(require("colors/safe"));
const utils = __importStar(require("./utils"));
const antiCheat_1 = require("./antiCheat");
// force type of post as promisify doesn't know which one it should take
const post = (0, util_1.promisify)(request_1.default.post);
const notify = async (challenge, cheatScore = -1, webhook = process.env.SOLUTIONS_WEBHOOK) => {
    if (!webhook) {
        return;
    }
    const res = await post(webhook, {
        json: {
            solution: {
                challenge: challenge.key,
                cheatScore,
                totalCheatScore: (0, antiCheat_1.totalCheatScore)(),
                issuedOn: new Date().toISOString()
            },
            ctfFlag: utils.ctfFlag(challenge.name),
            issuer: {
                hostName: os_1.default.hostname(),
                os: `${os_1.default.type()} (${os_1.default.release()})`,
                appName: config_1.default.get('application.name'),
                config: process.env.NODE_ENV ?? 'default',
                version: utils.version()
            }
        }
    });
    logger_1.default.info(`Webhook ${safe_1.default.bold(webhook)} notified about ${safe_1.default.cyan(challenge.key)} being solved: ${res.statusCode < 400 ? safe_1.default.green(res.statusCode.toString()) : safe_1.default.red(res.statusCode.toString())}`);
};
exports.notify = notify;
//# sourceMappingURL=webhook.js.map