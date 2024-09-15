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
const API_URL = 'http://localhost:3000/api';
const REST_URL = 'http://localhost:3000/rest';
describe('/api', () => {
    it('GET error when query /api without actual resource', () => {
        return frisby.get(API_URL)
            .expect('status', 500);
    });
});
describe('/rest', () => {
    it('GET error message with information leakage when calling unrecognized path with /rest in it', () => {
        return frisby.get(REST_URL + '/unrecognized')
            .expect('status', 500)
            .expect('bodyContains', '<h1>' + config_1.default.get('application.name') + ' (Express')
            .expect('bodyContains', 'Unexpected path: /rest/unrecognized');
    });
});
//# sourceMappingURL=apiSpec.js.map