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
describe('countryMapping', () => {
    const countryMapping = require('../../routes/countryMapping');
    let req;
    let res;
    beforeEach(() => {
        req = {};
        res = { send: sinon.spy(), status: sinon.stub().returns({ send: sinon.spy() }) };
    });
    it('should return configured country mappings', () => {
        countryMapping({ get: sinon.stub().withArgs('ctf.countryMapping').returns('TEST') })(req, res);
        expect(res.send).to.have.been.calledWith('TEST');
    });
    it('should return server error when configuration has no country mappings', () => {
        countryMapping({ get: sinon.stub().withArgs('ctf.countryMapping').returns(null) })(req, res);
        expect(res.status).to.have.been.calledWith(500);
    });
    it('should return ' + (config_1.default.get('ctf.countryMapping') ? 'no ' : '') + 'server error for active configuration from config/' + process.env.NODE_ENV + '.yml', () => {
        countryMapping()(req, res);
        if (config_1.default.get('ctf.countryMapping')) {
            expect(res.send).to.have.been.calledWith(config_1.default.get('ctf.countryMapping'));
        }
        else {
            expect(res.status).to.have.been.calledWith(500);
        }
    });
});
//# sourceMappingURL=countryMappingSpec.js.map