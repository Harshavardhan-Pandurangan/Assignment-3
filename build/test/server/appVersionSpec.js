"use strict";
/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const sinon = require("sinon");
const config_1 = __importDefault(require("config"));
const chai = require("chai");
const sinonChai = require("sinon-chai");
const expect = chai.expect;
chai.use(sinonChai);
describe('appVersion', () => {
    const retrieveAppVersion = require('../../routes/appVersion');
    let req;
    let res;
    it('should ' + config_1.default.get('application.showVersionNumber') ? '' : 'not ' + 'return version specified in package.json', () => {
        req = {};
        res = { json: sinon.spy() };
        retrieveAppVersion()(req, res);
        expect(res.json).to.have.been.calledWith({ version: config_1.default.get('application.showVersionNumber') ? require('../../package.json').version : '' });
    });
});
//# sourceMappingURL=appVersionSpec.js.map