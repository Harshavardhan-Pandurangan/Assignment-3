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
const fs = require("fs");
const user_1 = require("../models/user");
const logger_1 = __importDefault(require("../lib/logger"));
const utils = __importStar(require("../lib/utils"));
const security = require('../lib/insecurity');
const fileType = require('file-type');
module.exports = function fileUpload() {
    return async (req, res, next) => {
        const file = req.file;
        const buffer = file?.buffer;
        const uploadedFileType = await fileType.fromBuffer(buffer);
        if (uploadedFileType === undefined) {
            res.status(500);
            next(new Error('Illegal file type'));
        }
        else {
            if (uploadedFileType !== null && utils.startsWith(uploadedFileType.mime, 'image')) {
                const loggedInUser = security.authenticatedUsers.get(req.cookies.token);
                if (loggedInUser) {
                    fs.open(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${uploadedFileType.ext}`, 'w', function (err, fd) {
                        if (err != null)
                            logger_1.default.warn('Error opening file: ' + err.message);
                        // @ts-expect-error FIXME buffer has unexpected type
                        fs.write(fd, buffer, 0, buffer.length, null, function (err) {
                            if (err != null)
                                logger_1.default.warn('Error writing file: ' + err.message);
                            fs.close(fd, function () { });
                        });
                    });
                    user_1.UserModel.findByPk(loggedInUser.data.id).then(async (user) => {
                        if (user != null) {
                            return await user.update({ profileImage: `assets/public/images/uploads/${loggedInUser.data.id}.${uploadedFileType.ext}` });
                        }
                    }).catch((error) => {
                        next(error);
                    });
                    res.location(process.env.BASE_PATH + '/profile');
                    res.redirect(process.env.BASE_PATH + '/profile');
                }
                else {
                    next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
                }
            }
            else {
                res.status(415);
                next(new Error(`Profile image upload does not accept this file type${uploadedFileType ? (': ' + uploadedFileType.mime) : '.'}`));
            }
        }
    };
};
//# sourceMappingURL=profileImageFileUpload.js.map