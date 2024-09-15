"use strict";
/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
Object.defineProperty(exports, "__esModule", { value: true });
const mongodb_1 = require("../data/mongodb");
const security = require('../lib/insecurity');
module.exports.orderHistory = function orderHistory() {
    return async (req, res, next) => {
        const loggedInUser = security.authenticatedUsers.get(req.headers?.authorization?.replace('Bearer ', ''));
        if (loggedInUser?.data?.email && loggedInUser.data.id) {
            const email = loggedInUser.data.email;
            const updatedEmail = email.replace(/[aeiou]/gi, '*');
            const order = await mongodb_1.ordersCollection.find({ email: updatedEmail });
            res.status(200).json({ status: 'success', data: order });
        }
        else {
            next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
        }
    };
};
module.exports.allOrders = function allOrders() {
    return async (req, res, next) => {
        const order = await mongodb_1.ordersCollection.find();
        res.status(200).json({ status: 'success', data: order.reverse() });
    };
};
module.exports.toggleDeliveryStatus = function toggleDeliveryStatus() {
    return async (req, res, next) => {
        const deliveryStatus = !req.body.deliveryStatus;
        const eta = deliveryStatus ? '0' : '1';
        await mongodb_1.ordersCollection.update({ _id: req.params.id }, { $set: { delivered: deliveryStatus, eta } });
        res.status(200).json({ status: 'success' });
    };
};
//# sourceMappingURL=orderHistory.js.map