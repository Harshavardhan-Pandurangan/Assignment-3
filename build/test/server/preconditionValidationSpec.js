"use strict";
/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
Object.defineProperty(exports, "__esModule", { value: true });
const chai = require("chai");
const sinonChai = require("sinon-chai");
const validatePreconditions_1 = require("../../lib/startup/validatePreconditions");
const expect = chai.expect;
const net = require('net');
chai.use(sinonChai);
const semver = require('semver');
describe('preconditionValidation', () => {
    describe('checkIfRunningOnSupportedNodeVersion', () => {
        const supportedVersion = require('./../../package.json').engines.node;
        it('should define the supported semver range as 18 - 22', () => {
            expect(supportedVersion).to.equal('18 - 22');
            expect(semver.validRange(supportedVersion)).to.not.equal(null);
        });
        it('should accept a supported version', () => {
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('22.4.1')).to.equal(true);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('21.7.3')).to.equal(true);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('20.15.1')).to.equal(true);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('19.9.0')).to.equal(true);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('18.20.4')).to.equal(true);
        });
        it('should fail for an unsupported version', () => {
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('23.0.0')).to.equal(false);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('17.3.0')).to.equal(false);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('16.10.0')).to.equal(false);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('15.9.0')).to.equal(false);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('14.0.0')).to.equal(false);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('13.13.0')).to.equal(false);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('12.16.2')).to.equal(false);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('11.14.0')).to.equal(false);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('10.20.0')).to.equal(false);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('9.11.2')).to.equal(false);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('8.12.0')).to.equal(false);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('7.10.1')).to.equal(false);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('6.14.4')).to.equal(false);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('4.9.1')).to.equal(false);
            expect((0, validatePreconditions_1.checkIfRunningOnSupportedNodeVersion)('0.12.8')).to.equal(false);
        });
    });
    describe('checkIfPortIsAvailable', () => {
        it('should resolve when port 3000 is closed', async () => {
            const success = await (0, validatePreconditions_1.checkIfPortIsAvailable)(3000);
            expect(success).to.equal(true);
        });
        describe('open a server before running the test', () => {
            const testServer = net.createServer();
            before((done) => {
                testServer.listen(3000, done);
            });
            it('should reject when port 3000 is open', async () => {
                const success = await (0, validatePreconditions_1.checkIfPortIsAvailable)(3000);
                expect(success).to.equal(false);
            });
            after((done) => {
                testServer.close(done);
            });
        });
    });
});
//# sourceMappingURL=preconditionValidationSpec.js.map