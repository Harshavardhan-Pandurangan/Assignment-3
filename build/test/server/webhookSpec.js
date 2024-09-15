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
const webhook = __importStar(require("../../lib/webhook"));
const chai = require("chai");
const expect = chai.expect;
const chaiAsPromised = require('chai-as-promised');
chai.use(chaiAsPromised);
describe('webhook', () => {
    const challenge = {
        key: 'key',
        name: 'name',
        difficulty: 1
    };
    describe('notify', () => {
        it('fails when no webhook URL is provided via environment variable', () => {
            void expect(webhook.notify(challenge)).to.eventually.throw('options.uri is a required argument');
        });
        it('fails when supplied webhook is not a valid URL', () => {
            void expect(webhook.notify(challenge, 0, 'localhorst')).to.eventually.throw('Invalid URI "localhorst"');
        });
        it('submits POST with payload to existing URL', () => {
            void expect(webhook.notify(challenge, 0, 'https://enlm7zwniuyah.x.pipedream.net/')).to.eventually.not.throw();
        });
    });
});
//# sourceMappingURL=webhookSpec.js.map