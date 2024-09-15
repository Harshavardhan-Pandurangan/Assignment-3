"use strict";
/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const frisby = require("frisby");
const config_1 = __importDefault(require("config"));
const URL = 'http://localhost:3000';
describe('HTTP', () => {
    it('response must contain CORS header allowing all origins', () => {
        return frisby.get(URL)
            .expect('status', 200)
            .expect('header', 'Access-Control-Allow-Origin', '\\*');
    });
    it('response must contain sameorigin frameguard header', () => {
        return frisby.get(URL)
            .expect('status', 200)
            .expect('header', 'X-Frame-Options', 'SAMEORIGIN');
    });
    it('response must contain CORS header allowing all origins', () => {
        return frisby.get(URL)
            .expect('status', 200)
            .expect('header', 'X-Content-Type-Options', 'nosniff');
    });
    it('response must not contain recruiting header', () => {
        return frisby.get(URL)
            .expect('status', 200)
            .expect('header', 'X-Recruiting', config_1.default.get('application.securityTxt.hiring'));
    });
    it('response must not contain XSS protection header', () => {
        return frisby.get(URL)
            .expect('status', 200)
            .expectNot('header', 'X-XSS-Protection');
    });
});
//# sourceMappingURL=httpSpec.js.map