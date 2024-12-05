const axios = require('axios');

const getOAuthToken = async () => {
    try {
        const consumerKey = process.env.MPESA_CONSUMER_KEY;
        const consumerSecret = process.env.MPESA_CONSUMER_SECRET;

        if (!consumerKey || !consumerSecret) {
            throw new Error('M-Pesa credentials are missing');
        }

        const auth = Buffer.from(`${consumerKey}:${consumerSecret}`).toString('base64');
        
        const response = await axios({
            method: 'GET',
            url: 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            validateStatus: (status) => status < 500
        });

        if (response.status !== 200) {
            console.error('OAuth Error Response:', {
                status: response.status,
                data: response.data,
                headers: response.headers
            });
            throw new Error(`OAuth request failed with status ${response.status}`);
        }

        if (!response.data?.access_token) {
            throw new Error('Invalid OAuth response structure');
        }

        return response.data.access_token;
    } catch (error) {
        console.error('OAuth Error Details:', {
            message: error.message,
            status: error.response?.status,
            data: error.response?.data,
            headers: error.response?.headers
        });
        throw new Error(`OAuth token generation failed: ${error.message}`);
    }
};

const initiateSTKPush = async (phoneNumber, amount) => {
    try {
        if (!phoneNumber || !amount) {
            throw new Error('Phone number and amount are required');
        }

        const token = await getOAuthToken();
        
        const timestamp = new Date().toISOString()
            .replace(/[^0-9]/g, '')
            .slice(0, -3);
            
        const shortcode = process.env.MPESA_SHORTCODE || process.env.MPESA_LIPA_NA_MPESA_SHORTCODE;
        const passkey = process.env.MPESA_PASSKEY || process.env.MPESA_LIPA_NA_MPESA_PASSKEY;

        if (!shortcode || !passkey) {
            throw new Error('M-Pesa configuration missing');
        }

        // Validate and construct callback URL
        let callbackUrl = process.env.MPESA_CALLBACK_URL || process.env.BASE_URL;
        if (!callbackUrl) {
            throw new Error('Callback URL configuration is missing');
        }

        // Ensure the callback URL is properly formatted
        if (!callbackUrl.startsWith('http://') && !callbackUrl.startsWith('https://')) {
            callbackUrl = `https://${callbackUrl}`;
        }

        // Ensure the callback URL ends with the correct path
        if (!callbackUrl.endsWith('/api/mpesa/callback')) {
            callbackUrl = callbackUrl.replace(/\/?$/, '/api/mpesa/callback');
        }

        const password = Buffer.from(`${shortcode}${passkey}${timestamp}`).toString('base64');

        const requestBody = {
            BusinessShortCode: shortcode,
            Password: password,
            Timestamp: timestamp,
            TransactionType: "CustomerPayBillOnline",
            Amount: Math.round(amount),
            PartyA: phoneNumber,
            PartyB: shortcode,
            PhoneNumber: phoneNumber,
            CallBackURL: callbackUrl,
            AccountReference: "Twerandus Sacco",
            TransactionDesc: "Deposit"
        };

        console.log('STK Push Request:', {
            url: 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
            body: {
                ...requestBody,
                CallBackURL: callbackUrl // Log the actual callback URL being used
            }
        });

        const response = await axios({
            method: 'post',
            url: 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            data: requestBody,
            validateStatus: status => status < 500
        });

        console.log('STK Push Response:', {
            status: response.status,
            data: response.data
        });

        if (response.status !== 200) {
            throw new Error(`STK Push request failed with status ${response.status}: ${JSON.stringify(response.data)}`);
        }

        if (!response.data?.CheckoutRequestID) {
            throw new Error('Invalid STK Push response structure');
        }

        return response.data;
    } catch (error) {
        console.error('STK Push Error:', {
            message: error.message,
            response: error.response?.data,
            stack: error.stack
        });
        throw error;
    }
};

module.exports = {
    initiateSTKPush
};