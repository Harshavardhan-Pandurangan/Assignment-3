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
const challengeUtils = require("../lib/challengeUtils");
const config_1 = __importDefault(require("config"));
const utils = __importStar(require("../lib/utils"));
const html_entities_1 = require("html-entities");
const datacache_1 = require("../data/datacache");
const pug = require('pug');
const themes = require('../views/themes/themes').themes;
const entities = new html_entities_1.AllHtmlEntities();
exports.getVideo = () => {
    return (req, res) => {
        const path = videoPath();
        const stat = fs.statSync(path);
        const fileSize = stat.size;
        const range = req.headers.range;
        if (range) {
            const parts = range.replace(/bytes=/, '').split('-');
            const start = parseInt(parts[0], 10);
            const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
            const chunksize = (end - start) + 1;
            const file = fs.createReadStream(path, { start, end });
            const head = {
                'Content-Range': `bytes ${start}-${end}/${fileSize}`,
                'Accept-Ranges': 'bytes',
                'Content-Length': chunksize,
                'Content-Location': '/assets/public/videos/owasp_promo.mp4',
                'Content-Type': 'video/mp4'
            };
            res.writeHead(206, head);
            file.pipe(res);
        }
        else {
            const head = {
                'Content-Length': fileSize,
                'Content-Type': 'video/mp4'
            };
            res.writeHead(200, head);
            fs.createReadStream(path).pipe(res);
        }
    };
};
exports.promotionVideo = () => {
    return (req, res) => {
        fs.readFile('views/promotionVideo.pug', function (err, buf) {
            if (err != null)
                throw err;
            let template = buf.toString();
            const subs = getSubsFromFile();
            challengeUtils.solveIf(datacache_1.challenges.videoXssChallenge, () => { return utils.contains(subs, '</script><script>alert(`xss`)</script>'); });
            const theme = themes[config_1.default.get('application.theme')];
            template = template.replace(/_title_/g, entities.encode(config_1.default.get('application.name')));
            template = template.replace(/_favicon_/g, favicon());
            template = template.replace(/_bgColor_/g, theme.bgColor);
            template = template.replace(/_textColor_/g, theme.textColor);
            template = template.replace(/_navColor_/g, theme.navColor);
            template = template.replace(/_primLight_/g, theme.primLight);
            template = template.replace(/_primDark_/g, theme.primDark);
            const fn = pug.compile(template);
            let compiledTemplate = fn();
            compiledTemplate = compiledTemplate.replace('<script id="subtitle"></script>', '<script id="subtitle" type="text/vtt" data-label="English" data-lang="en">' + subs + '</script>');
            res.send(compiledTemplate);
        });
    };
    function favicon() {
        return utils.extractFilename(config_1.default.get('application.favicon'));
    }
};
function getSubsFromFile() {
    const subtitles = config_1.default.get('application.promotion.subtitles') ?? 'owasp_promo.vtt';
    const data = fs.readFileSync('frontend/dist/frontend/assets/public/videos/' + subtitles, 'utf8');
    return data.toString();
}
function videoPath() {
    if (config_1.default.get('application.promotion.video') !== null) {
        const video = utils.extractFilename(config_1.default.get('application.promotion.video'));
        return 'frontend/dist/frontend/assets/public/videos/' + video;
    }
    return 'frontend/dist/frontend/assets/public/videos/owasp_promo.mp4';
}
//# sourceMappingURL=videoHandler.js.map