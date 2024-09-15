"use strict";
/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const chai = require("chai");
const path_1 = __importDefault(require("path"));
const util_1 = require("util");
const sinonChai = require("sinon-chai");
const expect = chai.expect;
chai.use(sinonChai);
const fs = require('fs');
const { safeLoad } = require('js-yaml');
const readFile = (0, util_1.promisify)(fs.readFile);
const loadYamlFile = async (filename) => {
    const contents = await readFile(filename, { encoding: 'utf8' });
    return safeLoad(contents);
};
describe('challengeTutorialSequence', () => {
    let challenges;
    before(async () => {
        challenges = await loadYamlFile(path_1.default.resolve('data/static/challenges.yml'));
    });
    it('should have unique tutorial orders', async () => {
        const tutorialOrderCounts = {};
        for (const { tutorial } of challenges) {
            if (tutorial) {
                const order = tutorial.order;
                if (!Object.prototype.hasOwnProperty.call(tutorialOrderCounts, order)) {
                    tutorialOrderCounts[order] = 0;
                }
                tutorialOrderCounts[order]++;
            }
        }
        for (const order of Object.keys(tutorialOrderCounts)) {
            const count = tutorialOrderCounts[order];
            expect(count, `Tutorial order "${order}" is used for multiple challenges.`).to.equal(1);
        }
    });
});
//# sourceMappingURL=challengeTutorialSequenceSpec.js.map