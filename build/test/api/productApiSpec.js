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
const config_1 = __importDefault(require("config"));
const frisby = require("frisby");
const Joi = frisby.Joi;
const utils = require('../../lib/utils');
const security = require('../../lib/insecurity');
// array index of the items is incremented by one because the db id starts with 1
const tamperingProductId = config_1.default.get('products').findIndex((product) => !!product.urlForProductTamperingChallenge) + 1;
const API_URL = 'http://localhost:3000/api';
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' };
const jsonHeader = { 'content-type': 'application/json' };
describe('/api/Products', () => {
    it('GET all products', () => {
        return frisby.get(API_URL + '/Products')
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('jsonTypes', 'data.*', {
            id: Joi.number(),
            name: Joi.string(),
            description: Joi.string(),
            price: Joi.number(),
            deluxePrice: Joi.number(),
            image: Joi.string()
        });
    });
    it('POST new product is forbidden via public API', () => {
        return frisby.post(API_URL + '/Products', {
            name: 'Dirt Juice (1000ml)',
            description: 'Made from ugly dirt.',
            price: 0.99,
            image: 'dirt_juice.jpg'
        })
            .expect('status', 401);
    });
    if (utils.isChallengeEnabled(datacache_1.challenges.restfulXssChallenge)) {
        it('POST new product does not filter XSS attacks', () => {
            return frisby.post(API_URL + '/Products', {
                headers: authHeader,
                body: {
                    name: 'XSS Juice (42ml)',
                    description: '<iframe src="javascript:alert(`xss`)">',
                    price: 9999.99,
                    image: 'xss3juice.jpg'
                }
            })
                .expect('header', 'content-type', /application\/json/)
                .expect('json', 'data', { description: '<iframe src="javascript:alert(`xss`)">' });
        });
    }
});
describe('/api/Products/:id', () => {
    it('GET existing product by id', () => {
        return frisby.get(API_URL + '/Products/1')
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('jsonTypes', 'data', {
            id: Joi.number(),
            name: Joi.string(),
            description: Joi.string(),
            price: Joi.number(),
            deluxePrice: Joi.number(),
            image: Joi.string(),
            createdAt: Joi.string(),
            updatedAt: Joi.string()
        })
            .expect('json', 'data', { id: 1 });
    });
    it('GET non-existing product by id', () => {
        return frisby.get(API_URL + '/Products/4711')
            .expect('status', 404)
            .expect('header', 'content-type', /application\/json/)
            .expect('json', 'message', 'Not Found');
    });
    it('PUT update existing product is possible due to Missing Function-Level Access Control vulnerability', () => {
        return frisby.put(API_URL + '/Products/' + tamperingProductId, {
            header: jsonHeader,
            body: {
                description: '<a href="http://kimminich.de" target="_blank">More...</a>'
            }
        })
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('json', 'data', { description: '<a href="http://kimminich.de" target="_blank">More...</a>' });
    });
    xit('PUT update existing product does not filter XSS attacks', () => {
        return frisby.put(API_URL + '/Products/1', {
            header: jsonHeader,
            body: {
                description: '<script>alert(\'XSS\')</script>'
            }
        })
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('json', 'data', { description: '<script>alert(\'XSS\')</script>' });
    });
    it('DELETE existing product is forbidden via public API', () => {
        return frisby.del(API_URL + '/Products/1')
            .expect('status', 401);
    });
    it('DELETE existing product is forbidden via API even when authenticated', () => {
        return frisby.del(API_URL + '/Products/1', { headers: authHeader })
            .expect('status', 401);
    });
});
//# sourceMappingURL=productApiSpec.js.map