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
const os_1 = __importDefault(require("os"));
const fs = require("fs");
const challengeUtils = require("../lib/challengeUtils");
const path_1 = __importDefault(require("path"));
const utils = __importStar(require("../lib/utils"));
const datacache_1 = require("../data/datacache");
const libxml = require('libxmljs');
const vm = require('vm');
const unzipper = require('unzipper');
function ensureFileIsPassed({ file }, res, next) {
    if (file != null) {
        next();
    }
}
function handleZipFileUpload({ file }, res, next) {
    if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
        if (((file?.buffer) != null) && utils.isChallengeEnabled(datacache_1.challenges.fileWriteChallenge)) {
            const buffer = file.buffer;
            const filename = file.originalname.toLowerCase();
            const tempFile = path_1.default.join(os_1.default.tmpdir(), filename);
            fs.open(tempFile, 'w', function (err, fd) {
                if (err != null) {
                    next(err);
                }
                fs.write(fd, buffer, 0, buffer.length, null, function (err) {
                    if (err != null) {
                        next(err);
                    }
                    fs.close(fd, function () {
                        fs.createReadStream(tempFile)
                            .pipe(unzipper.Parse())
                            .on('entry', function (entry) {
                            const fileName = entry.path;
                            const absolutePath = path_1.default.resolve('uploads/complaints/' + fileName);
                            challengeUtils.solveIf(datacache_1.challenges.fileWriteChallenge, () => { return absolutePath === path_1.default.resolve('ftp/legal.md'); });
                            if (absolutePath.includes(path_1.default.resolve('.'))) {
                                entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName).on('error', function (err) { next(err); }));
                            }
                            else {
                                entry.autodrain();
                            }
                        }).on('error', function (err) { next(err); });
                    });
                });
            });
        }
        res.status(204).end();
    }
    else {
        next();
    }
}
function checkUploadSize({ file }, res, next) {
    if (file != null) {
        challengeUtils.solveIf(datacache_1.challenges.uploadSizeChallenge, () => { return file?.size > 100000; });
    }
    next();
}
function checkFileType({ file }, res, next) {
    const fileType = file?.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase();
    challengeUtils.solveIf(datacache_1.challenges.uploadTypeChallenge, () => {
        return !(fileType === 'pdf' || fileType === 'xml' || fileType === 'zip');
    });
    next();
}
function handleXmlUpload({ file }, res, next) {
    if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
        challengeUtils.solveIf(datacache_1.challenges.deprecatedInterfaceChallenge, () => { return true; });
        if (((file?.buffer) != null) && utils.isChallengeEnabled(datacache_1.challenges.deprecatedInterfaceChallenge)) { // XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes
            const data = file.buffer.toString();
            try {
                const sandbox = { libxml, data };
                vm.createContext(sandbox);
                const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 });
                const xmlString = xmlDoc.toString(false);
                challengeUtils.solveIf(datacache_1.challenges.xxeFileDisclosureChallenge, () => { return (utils.matchesEtcPasswdFile(xmlString) || utils.matchesSystemIniFile(xmlString)); });
                res.status(410);
                next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(xmlString, 400) + ' (' + file.originalname + ')'));
            }
            catch (err) { // TODO: Remove any
                if (utils.contains(err.message, 'Script execution timed out')) {
                    if (challengeUtils.notSolved(datacache_1.challenges.xxeDosChallenge)) {
                        challengeUtils.solve(datacache_1.challenges.xxeDosChallenge);
                    }
                    res.status(503);
                    next(new Error('Sorry, we are temporarily not available! Please try again later.'));
                }
                else {
                    res.status(410);
                    next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + err.message + ' (' + file.originalname + ')'));
                }
            }
        }
        else {
            res.status(410);
            next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'));
        }
    }
    res.status(204).end();
}
module.exports = {
    ensureFileIsPassed,
    handleZipFileUpload,
    checkUploadSize,
    checkFileType,
    handleXmlUpload
};
//# sourceMappingURL=fileUpload.js.map