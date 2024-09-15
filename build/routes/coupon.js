"use strict";
/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
Object.defineProperty(exports, "__esModule", { value: true });
const basket_1 = require("../models/basket");
const security = require('../lib/insecurity');
module.exports = function applyCoupon() {
    return ({ params }, res, next) => {
        const id = params.id;
        let coupon = params.coupon ? decodeURIComponent(params.coupon) : undefined;
        const discount = security.discountFromCoupon(coupon);
        coupon = discount ? coupon : null;
        basket_1.BasketModel.findByPk(id).then((basket) => {
            if (basket != null) {
                basket.update({ coupon: coupon?.toString() }).then(() => {
                    if (discount) {
                        res.json({ discount });
                    }
                    else {
                        res.status(404).send('Invalid coupon.');
                    }
                }).catch((error) => {
                    next(error);
                });
            }
            else {
                next(new Error('Basket with id=' + id + ' does not exist.'));
            }
        }).catch((error) => {
            next(error);
        });
    };
};
//# sourceMappingURL=coupon.js.map