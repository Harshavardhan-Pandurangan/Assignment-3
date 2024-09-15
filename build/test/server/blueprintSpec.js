"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const chai = require("chai");
const config_1 = __importDefault(require("config"));
const path_1 = __importDefault(require("path"));
const util_1 = require("util");
const exif_1 = require("exif");
const sinonChai = require("sinon-chai");
const expect = chai.expect;
chai.use(sinonChai);
const fs = require('fs');
const utils = require('../../lib/utils');
const { pipeline } = require('stream');
const fetch = require('node-fetch');
async function parseExifData(path) {
    return await new Promise((resolve, reject) => {
        // eslint-disable-next-line no-new
        new exif_1.ExifImage({ image: path }, (error, exifData) => {
            if (error != null) {
                expect.fail(`Could not read EXIF data from ${path}`);
                reject(error);
            }
            resolve(exifData);
        });
    });
}
describe('blueprint', () => {
    const products = config_1.default.get('products');
    let pathToImage = 'assets/public/images/products/';
    describe('checkExifData', () => {
        it('should contain properties from exifForBlueprintChallenge', async () => {
            for (const product of products) {
                if (product.fileForRetrieveBlueprintChallenge && product.image) {
                    if (utils.isUrl(product.image)) {
                        pathToImage = path_1.default.resolve('frontend/dist/frontend', pathToImage, product.image.substring(product.image.lastIndexOf('/') + 1));
                        const streamPipeline = (0, util_1.promisify)(pipeline);
                        const response = await fetch(product.image);
                        if (!response.ok)
                            expect.fail(`Could not download image from ${product.image}`);
                        await streamPipeline(response.body, fs.createWriteStream(pathToImage));
                    }
                    else {
                        pathToImage = path_1.default.resolve('frontend/src', pathToImage, product.image);
                    }
                    if (product.exifForBlueprintChallenge?.[0]) { // Prevents failing test for sample or custom themes where null has been explicitly set as value for "exifForBlueprintChallenge". Warning: This makes the "Retrieve Blueprint" challenge probably unsolvable unless hints are placed elsewhere.
                        try {
                            const exifData = await parseExifData(pathToImage);
                            const properties = Object.values(exifData.image);
                            for (const property of product.exifForBlueprintChallenge) {
                                expect(properties).to.include(property);
                            }
                        }
                        catch (error) {
                            expect.fail(`Could not read EXIF data from ${pathToImage}`);
                        }
                    }
                }
            }
        });
    });
});
//# sourceMappingURL=blueprintSpec.js.map