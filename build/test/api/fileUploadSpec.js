"use strict";
/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const datacache_1 = require("../../data/datacache");
const globals_1 = require("@jest/globals");
const frisby = require("frisby");
const path_1 = __importDefault(require("path"));
const fs = require('fs');
const utils = require('../../lib/utils');
const URL = 'http://localhost:3000';
describe('/file-upload', () => {
    it('POST file valid PDF for client and API', () => {
        const file = path_1.default.resolve(__dirname, '../files/validSizeAndTypeForClient.pdf');
        const form = frisby.formData();
        form.append('file', fs.createReadStream(file));
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 204);
    });
    it('POST file too large for client validation but valid for API', () => {
        const file = path_1.default.resolve(__dirname, '../files/invalidSizeForClient.pdf');
        const form = frisby.formData();
        form.append('file', fs.createReadStream(file));
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 204);
    });
    it('POST file with illegal type for client validation but valid for API', () => {
        const file = path_1.default.resolve(__dirname, '../files/invalidTypeForClient.exe');
        const form = frisby.formData();
        form.append('file', fs.createReadStream(file));
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 204);
    });
    it('POST file type XML deprecated for API', () => {
        const file = path_1.default.resolve(__dirname, '../files/deprecatedTypeForServer.xml');
        const form = frisby.formData();
        form.append('file', fs.createReadStream(file));
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 410);
    });
    it('POST large XML file near upload size limit', () => {
        const file = path_1.default.resolve(__dirname, '../files/maxSizeForServer.xml');
        const form = frisby.formData();
        form.append('file', fs.createReadStream(file));
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 410);
    });
    if (utils.isChallengeEnabled(datacache_1.challenges.xxeFileDisclosureChallenge) || utils.isChallengeEnabled(datacache_1.challenges.xxeDosChallenge)) {
        it('POST file type XML with XXE attack against Windows', () => {
            const file = path_1.default.resolve(__dirname, '../files/xxeForWindows.xml');
            const form = frisby.formData();
            form.append('file', fs.createReadStream(file));
            return frisby.post(URL + '/file-upload', {
                // @ts-expect-error FIXME form.getHeaders() is not found
                headers: { 'Content-Type': form.getHeaders()['content-type'] },
                body: form
            })
                .expect('status', 410);
        });
        it('POST file type XML with XXE attack against Linux', () => {
            const file = path_1.default.resolve(__dirname, '../files/xxeForLinux.xml');
            const form = frisby.formData();
            form.append('file', fs.createReadStream(file));
            return frisby.post(URL + '/file-upload', {
                // @ts-expect-error FIXME form.getHeaders() is not found
                headers: { 'Content-Type': form.getHeaders()['content-type'] },
                body: form
            })
                .expect('status', 410);
        });
        it('POST file type XML with Billion Laughs attack is caught by parser', () => {
            const file = path_1.default.resolve(__dirname, '../files/xxeBillionLaughs.xml');
            const form = frisby.formData();
            form.append('file', fs.createReadStream(file));
            return frisby.post(URL + '/file-upload', {
                // @ts-expect-error FIXME form.getHeaders() is not found
                headers: { 'Content-Type': form.getHeaders()['content-type'] },
                body: form
            })
                .expect('status', 410)
                .expect('bodyContains', 'Detected an entity reference loop');
        });
        it('POST file type XML with Quadratic Blowup attack', () => {
            const file = path_1.default.resolve(__dirname, '../files/xxeQuadraticBlowup.xml');
            const form = frisby.formData();
            form.append('file', fs.createReadStream(file));
            return frisby.post(URL + '/file-upload', {
                // @ts-expect-error FIXME form.getHeaders() is not found
                headers: { 'Content-Type': form.getHeaders()['content-type'] },
                body: form
            }).then((res) => {
                (0, globals_1.expect)(res.status).toBeGreaterThanOrEqual(410); // usually runs into 410 on Travis-CI but into 503 locally
            });
        });
        it('POST file type XML with dev/random attack', () => {
            const file = path_1.default.resolve(__dirname, '../files/xxeDevRandom.xml');
            const form = frisby.formData();
            form.append('file', fs.createReadStream(file));
            return frisby.post(URL + '/file-upload', {
                // @ts-expect-error FIXME form.getHeaders() is not found
                headers: { 'Content-Type': form.getHeaders()['content-type'] },
                body: form
            });
        });
    }
    it('POST file too large for API', () => {
        const file = path_1.default.resolve(__dirname, '../files/invalidSizeForServer.pdf');
        const form = frisby.formData();
        form.append('file', fs.createReadStream(file));
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 500);
    });
    it('POST zip file with directory traversal payload', () => {
        const file = path_1.default.resolve(__dirname, '../files/arbitraryFileWrite.zip');
        const form = frisby.formData();
        form.append('file', fs.createReadStream(file));
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 204);
    });
    it('POST zip file with password protection', () => {
        const file = path_1.default.resolve(__dirname, '../files/passwordProtected.zip');
        const form = frisby.formData();
        form.append('file', fs.createReadStream(file));
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 204);
    });
});
//# sourceMappingURL=fileUploadSpec.js.map