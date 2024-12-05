const express = require('express');
const router = express.Router();
const { initiateSTKPush } = require('../utils/mpesaUtils');
const verifyToken = require('../middleware/verifyToken');

router.post('/stkPush', verifyToken, async (req, res) => {
    try {
        const { amount, phone } = req.body;

        // Enhanced input validation
        if (!amount || !phone) {
            return res.status(400).json({
                success: false,
                message: 'Amount and phone number are required'
            });
        }

        // Format phone number - remove leading zeros, +, and ensure 254 prefix
        let formattedPhone = phone.replace(/^\+?254|^0/, '254');

        // Strict phone number validation
        const phoneRegex = /^254[71][0-9]{8}$/;
        if (!phoneRegex.test(formattedPhone)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid phone number format. Must be in format 254XXXXXXXXX'
            });
        }

        // Amount validation
        const numAmount = Number(amount);
        if (isNaN(numAmount) || numAmount < 1 || numAmount > 150000) {
            return res.status(400).json({
                success: false,
                message: 'Amount must be between 1 and 150,000'
            });
        }

        const stkResponse = await initiateSTKPush(formattedPhone, numAmount);

        res.json({
            success: true,
            message: 'STK Push initiated successfully',
            data: {
                CheckoutRequestID: stkResponse.CheckoutRequestID,
                ResponseDescription: stkResponse.ResponseDescription,
                CustomerMessage: stkResponse.CustomerMessage
            }
        });

    } catch (error) {
        console.error('Payment Error:', {
            message: error.message,
            stack: error.stack
        });

        // Enhanced error responses
        if (error.message.includes('OAuth')) {
            return res.status(500).json({
                success: false,
                message: 'Payment service authentication failed',
                error: 'Authentication error'
            });
        }

        if (error.message.includes('configuration missing')) {
            return res.status(500).json({
                success: false,
                message: 'Payment service misconfigured',
                error: 'Configuration error'
            });
        }

        res.status(500).json({
            success: false,
            message: 'Failed to initiate payment',
            error: error.message
        });
    }
});

module.exports = router;