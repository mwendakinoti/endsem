require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
const router = express.Router();
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
console.log('JWT_SECRET:', JWT_SECRET);
const mpesaRoutes = require('./routes/mpesaRoutes');

console.log('M-Pesa Configuration Check:', {
    consumerKeyPresent: !!process.env.MPESA_CONSUMER_KEY,
    consumerSecretPresent: !!process.env.MPESA_CONSUMER_SECRET,
    shortcodePresent: !!process.env.MPESA_LIPA_NA_MPESA_SHORTCODE,
    passkeyPresent: !!process.env.MPESA_LIPA_NA_MPESA_PASSKEY,
    baseUrl: process.env.BASE_URL
});
// Middleware
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public'), {
    index: 'login.html'
  }));
app.use(cors());
app.use('/mpesa', mpesaRoutes);
app.use(express.json()); // Parses JSON requests
app.use(express.urlencoded({ extended: true })); // Parses URL-encoded requests
// MongoDB Connection - Updated version
const MONGO_URI = process.env.MONGO_URI; // You'll set this in .env file

const connectDB = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('Connected to MongoDB Atlas');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
};

connectDB();


// User Schema and Model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    guarantor: { type: String, default: 'N/A' },
    balance: { type: Number, default: 0 },
    shares: { type: Number, default: 0 },
    phoneNumber: { type: String, required: true, unique: true },
    accountBalance: {
        type: Number,
        default: 0
      },
      accountTransactions: [{
        type: {
          type: String,
          enum: ['deposit', 'withdrawal', 'loan_transfer']
        },
        amount: Number,
        date: {
          type: Date,
          default: Date.now
        },
        description: String
      }]
    });
    
const User = mongoose.model('User', userSchema);

// Deposit Schema and Model
const depositSchema = new mongoose.Schema({
    username: { type: String, required: true },
    amount: { type: Number, required: true },
    time: { type: Date, default: Date.now },
    mpesaMessage: { type: String, required: true },
    status: { type: String, default: 'pending', enum: ['pending', 'approved', 'rejected'] },
    balance: { type: Number, default: 0 }
});
const Deposit = mongoose.model('Deposit', depositSchema);

// Withdraw Schema and Model
const withdrawSchema = new mongoose.Schema({
    username: { type: String, required: true },
    amount: { type: Number, required: true },
    phoneNumber: { type: String, required: true },
    time: { type: Date, default: Date.now },
    status: { type: String, default: 'pending', enum: ['pending', 'approved', 'rejected', 'completed'] }
});
const Withdraw = mongoose.model('Withdraw', withdrawSchema);

// Loan Request Schema and Model
const loanRequestSchema = new mongoose.Schema({
    username: { type: String, required: true },
    amount: { type: Number, required: true },
    duration: { type: Number, required: true },
    interestRate: { type: Number, required: true },
    totalRepayment: { type: Number, required: true },
    monthlyRepayment: { type: Number, required: true },
    time: { type: Date, default: Date.now },
    status: { type: String, default: 'pending', enum: ['pending', 'approved', 'rejected'] }
});
const LoanRequest = mongoose.model('LoanRequest', loanRequestSchema);

// Customer Feedback Schema and Model
const feedbackSchema = new mongoose.Schema({
    username: { type: String, required: true },
    message: { type: String, required: true },
    time: { type: Date, default: Date.now },
    read: { type: Boolean, default: false }
})
const Feedback = mongoose.model('Feedback', feedbackSchema);

// Chat Message Schema and Model
const chatMessageSchema = new mongoose.Schema({
    username: { type: String, required: true },
    message: { type: String, required: true },
    recipient: { type: String, default: 'all' }, // 'all' means public message
    time: { type: Date, default: Date.now }
});
const ChatMessage = mongoose.model('ChatMessage', chatMessageSchema);

const adminSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    }
});

const Admin = mongoose.model('Admin', adminSchema);

module.exports = Admin;
 
const approvedTransactionSchema = new mongoose.Schema({
    username: { type: String, required: true },
    type: { type: String, required: true }, // 'deposit', 'withdrawal', 'buy shares', etc.
    amount: { type: Number, required: true },
    date: { type: Date, default: Date.now }
});

const shareSchema = new mongoose.Schema({
    username: { type: String, required: true },
    amount: { type: Number, required: true },
    cost: { type: Number, required: true },
    purchaseDate: { type: Date, default: Date.now },
    paymentMethod: { type: String, required: true }
});
const Share = mongoose.model('Share', shareSchema);

const pendingSharePurchaseSchema = new mongoose.Schema({
    username: { type: String, required: true },
    amount: { type: Number, required: true },
    mpesaMessage: { type: String, required: true },
    status: { type: String, default: 'pending', enum: ['pending', 'approved', 'rejected'] },
    createdAt: { type: Date, default: Date.now }
});
const exitNotificationSchema = new mongoose.Schema({
    username: { type: String, required: true },
    exitDate: { type: Date, default: Date.now },
    userData: { type: mongoose.Schema.Types.Mixed } // Store user data for potential reinstatement
});
const ExitNotification = mongoose.model('ExitNotification', exitNotificationSchema);

const PendingSharePurchase = mongoose.model('PendingSharePurchase', pendingSharePurchaseSchema);
const ApprovedTransaction = mongoose.model('ApprovedTransaction', approvedTransactionSchema);


const mgrSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    participants: [{ type: String }],
    monthlyAmount: { type: Number, required: true },
    startDate: { type: Date, required: true },
    schedule: [{
      month: Date,
      recipient: String,
      payments: [{
        from: String,
        status: { type: String, enum: ['pending', 'sent', 'received'] }
      }]
    }]
  });
  
  const MGR = mongoose.model('MGR', mgrSchema);
 

const notificationSchema = new mongoose.Schema({
  username: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, required: true },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const Notification = mongoose.model('Notification', notificationSchema);

module.exports = Notification;

// Middleware to verify JWT token
function verifyToken(req, res, next) {
    console.log('verifyToken middleware hit');
    const token = req.header('Authorization')?.replace('Bearer ', '');
    console.log('Received token:', token);
  
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
  
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      console.log('Token verified successfully:', decoded);
      req.user = decoded;
      next();
    } catch (error) {
      console.error('Token verification failed:', error);
      res.status(401).json({ success: false, message: 'Invalid token' });
    }
  }
  // Loan Schema (as you've defined)
  const loanSchema = new mongoose.Schema({
    borrower: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
      },
      lender: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
      },
      amount: {
        type: Number,
        required: true
      },
      status: {
        type: String,
        enum: ['pending', 'approved', 'funded', 'repaying', 'completed', 'rejected'],
        default: 'pending'
      },
      interestRate: Number,
      term: Number,
      totalRepaymentAmount: Number,
      monthlyRepayment: Number,
      fundedAt: Date
    });
  
  const p2pLoan = mongoose.model('p2pLoan', loanSchema);
  
  // API Endpoint to create loan request
  let loanRequests = [];

 app.post('/api/loan-requests', async (req, res) => {
    try {
        const loanData = req.body;

        // Basic validation
        if (!loanData.borrowerName || !loanData.borrowerEmail) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        if (loanData.loanAmount <= 0 || loanData.interestRate <= 0) {
            return res.status(400).json({ message: 'Invalid loan amount or interest rate' });
        }

        // Create a new loan document using the Mongoose model
        const newLoan = new p2pLoan({
            borrower: null, // You'll need to associate with a user
            lender: null,   // You'll need to associate with a user
            amount: loanData.loanAmount,
            interestRate: loanData.interestRate,
            term: loanData.loanTerm,
            totalRepaymentAmount: loanData.totalRepayment,
            monthlyRepayment: loanData.monthlyRepayment,
            status: 'pending'
        });

        // Save the loan to the database
        await newLoan.save();

        // Optionally, you can still push to loanRequests array if needed
        loanRequests.push(loanData);

        // Return successful response
        res.status(201).json({
            message: 'Loan request submitted successfully',
            loanRequest: newLoan
        });

    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ 
            message: 'Internal server error', 
            error: error.message 
        });
    }
});

// Get all loan requests
app.get('/api/loan-requests', (req, res) => {
    res.json(loanRequests);
});

  // API Endpoint to get loan requests by email
  app.get('/api/loan-requests/:email', async (req, res) => {
    try {
      const p2ploan = await p2pLoan.find({ 
        borrowerEmail: req.params.email 
      });
      res.json(p2ploan);
    } catch (error) {
      console.error('Error fetching loan requests:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });
  
  app.post('/api/loans/fund', async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
  
    try {
      const { loanId, lenderId } = req.body;
  
      // Find the loan and populate borrower and lender details
      const loan = await Loan.findById(loanId)
        .populate('borrower')
        .populate('lender');
  
      if (!loan) {
        throw new Error('Loan not found');
      }
  
      // Find the lender's account
      const lender = await User.findById(lenderId);
  
      // Validate lender has sufficient balance
      if (lender.accountBalance < loan.amount) {
        return res.status(400).json({
          message: 'Insufficient balance to fund the loan'
        });
      }
  
      // Deduct amount from lender's account
      lender.accountBalance -= loan.amount;
      lender.accountTransactions.push({
        type: 'loan_transfer',
        amount: -loan.amount,
        description: `Loan funded to ${loan.borrower.username}`
      });
  
      // Credit amount to borrower's account
      const borrower = await User.findById(loan.borrower._id);
      borrower.accountBalance += loan.amount;
      borrower.accountTransactions.push({
        type: 'loan_transfer',
        amount: loan.amount,
        description: `Loan received from ${lender.username}`
      });
  
      // Update loan status
      loan.status = 'funded';
      loan.fundedAt = new Date();
  
      // Save all changes
      await lender.save({ session });
      await borrower.save({ session });
      await loan.save({ session });
  
      // Commit transaction
      await session.commitTransaction();
      session.endSession();
  
      res.status(200).json({
        message: 'Loan funded successfully',
        loan,
        lenderRemainingBalance: lender.accountBalance
      });
  
    } catch (error) {
      // Abort transaction
      await session.abortTransaction();
      session.endSession();
  
      console.error('Loan funding error:', error);
      res.status(500).json({
        message: 'Failed to fund loan',
        error: error.message
      });
    }
  });

  // Example backend route
app.get('/api/loans/:loanId', async (req, res) => {
    try {
      const loan = await Loan.findById(req.params.loanId)
        .populate('borrower', 'username')
        .populate('lender', '_id');
      
      if (!loan) {
        return res.status(404).json({ message: 'Loan not found' });
      }
  
      // Only return loan details if current user is the lender
      if (loan.lender._id.toString() !== req.user._id.toString()) {
        return res.status(403).json({ message: 'Unauthorized' });
      }
  
      res.json({
        lender: loan.lender._id,
        borrowerUsername: loan.borrower.username,
        // other loan details
      });
    } catch (error) {
      res.status(500).json({ message: 'Server error' });
    }
  });

  // API endpoint to get loan requests for a specific lender
app.get('/api/loan-requests/for-lender/:userId', async (req, res) => {
    try {
        const loanRequests = await Loan.find({ 
            lender: req.params.userId, 
            status: 'pending' 
        }).populate('borrower', 'username');
        
        res.json(loanRequests);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/loans/:loanId/approve', async (req, res) => {
    try {
        const loan = await p2pLoan.findByIdAndUpdate(
            req.params.loanId, 
            { status: 'approved' }, 
            { new: true }
        );

        if (!loan) {
            return res.status(404).json({ success: false, message: 'Loan not found' });
        }

        res.json({ 
            success: true, 
            message: 'Loan approved successfully', 
            loan 
        });
    } catch (error) {
        console.error('Loan approval error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to approve loan' 
        });
    }
});
  async function createNotification(username, message, type) {
    if (!username) {
      console.error('Username is undefined in createNotification');
      return;
    }
    const notification = new Notification({
      username: username,
      message,
      type
    });
    await notification.save();
  }
  function generateSchedule(participants, startDate, monthlyAmount) {
    const schedule = [];
    const startDateObj = new Date(startDate);
    
    for (let i = 0; i < participants.length; i++) {
        const month = new Date(startDateObj.getFullYear(), startDateObj.getMonth() + i, 1);
        const recipient = participants[i];
        schedule.push({
            month,
            recipient,
            amount: monthlyAmount
        });
    }

    return schedule;
}

// Middleware for checking if the user is an admin
const checkAdmin = (req, res, next) => {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).json({ auth: false, message: 'Admin access required.' });
    }
    next();
};

function isAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') {
        next();
      } else {
        res.status(403).json({ success: false, message: 'Access denied. Admin only.' });
      }
    };

// Register endpoint
app.post('/register', async (req, res) => {
    try {
        const { username, email, password, guarantor, phoneNumber } = req.body;

        // Input validation
        if (!username || !email || !password || !phoneNumber) {
            return res.status(400).json({ success: false, message: 'All fields are required' });
        }
        if (!username || !email || !password || !phoneNumber) {
            return res.status(400).json({ success: false, message: 'All fields are required' });
          }
        // Check for existing user
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Username or email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword, guarantor, phoneNumber });

        await newUser.save();
        const token = jwt.sign({ userId: newUser._id }, JWT_SECRET, { expiresIn: '1h' });
        console.log('Generated token:', token);
        res.status(201).json({ success: true, message: 'User registered successfully', token });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ success: false, message: 'Error registering user' });
    }
});
// Login endpoint
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Check for user in User model
        let user = await User.findOne({ username });
        
        if (!user) {
            // If not found in User model, check Admin model
            user = await Admin.findOne({ username });
        }

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const isAdmin = user.isAdmin || user.constructor.modelName === 'Admin';
        const token = jwt.sign(
            { id: user._id, username: user.username, isAdmin },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({
            success: true,
            message: 'Login successful',
            token,
            isAdmin
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// STK Push Handler
// STK Push Handler
app.post('/api/deposit', async (req, res) => {
    try {
        const { username, amount, phoneNumber } = req.body;

        // Validate input
        if (!username || !amount || !phoneNumber) {
            return res.status(400).send('Missing required fields');
        }

        // Save the deposit as pending
        const deposit = new Deposit({
            username,
            amount: 0, // Amount is updated on callback
            phoneNumber, // Add phone number
            status: 'pending', // Status is pending until callback confirms
            createdAt: new Date(),
        });
        await deposit.save();
        console.log('Pending deposit saved:', deposit);

        // Initiate STK Push
        const timestamp = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
        const password = Buffer.from(`${shortCode}${passkey}${timestamp}`).toString('base64');
        const stkPushRequest = {
            url: 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
            body: {
                BusinessShortCode: shortCode,
                Password: password,
                Timestamp: timestamp,
                TransactionType: 'CustomerPayBillOnline',
                Amount: amount,
                PartyA: phoneNumber,
                PartyB: shortCode,
                PhoneNumber: phoneNumber,
                CallBackURL: `${baseUrl}/api/mpesa/callback`,
                AccountReference: 'Twerandus Sacco',
                TransactionDesc: 'Deposit',
            },
        };

        // Make the request
        const response = await axios.post(stkPushRequest.url, stkPushRequest.body, {
            headers: { Authorization: `Bearer ${accessToken}` },
        });
        console.log('STK Push Response:', response.data);
        res.status(200).json({ message: 'STK Push initiated', data: response.data });
    } catch (error) {
        console.error('Error during STK Push:', error);
        res.status(500).send('STK Push failed');
    }
});



app.post('/mpesa/stkPush', async (req, res) => {
    try {
        const { username, amount, mpesaMessage } = req.body;

        // Save deposit to MongoDB
        const deposit = new Deposit({
            username: paymentData.username,
            amount: paymentData.amount,
            mpesaMessage: response.data.CheckoutRequestID,
            status: 'approved',
        });
        await deposit.save();

        res.status(200).json({
            success: true,
            message: 'Deposit saved successfully',
            deposit,
        });
    } catch (error) {
        console.error('Error handling /mpesa/stkPush:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Withdraw endpoint
app.post('/withdraw', verifyToken, async (req, res) => {
    const { amount } = req.body;
    const username = req.user.username;

    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        if (user.balance < amount) {
            return res.status(400).json({ success: false, message: 'Insufficient funds' });
        }

        // Subtract the amount from the user's balance
        user.balance -= amount;
        await user.save();

        const newWithdrawal = new Withdraw({ 
            username, 
            amount, 
            phoneNumber: user.phoneNumber 
        });
        await newWithdrawal.save();

        // Create a new transaction record
        const newTransaction = new ApprovedTransaction({
            username: user.username,
            type: 'withdrawal',
            amount: amount
        });
        await newTransaction.save();

        res.json({ success: true, message: 'Withdrawal request submitted successfully', newBalance: user.balance });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Loan application endpoint
app.post('/loan', verifyToken, async (req, res) => {
    const { loanAmount, loanDuration, interestRate, totalRepayment, monthlyRepayment } = req.body;
    const username = req.user.username;

    try {
        const newLoanRequest = new LoanRequest({
            username,
            amount: loanAmount,
            duration: loanDuration,
            interestRate,
            totalRepayment,
            monthlyRepayment,
            status: 'pending'
        });

        await newLoanRequest.save();
        res.json({ success: true, message: 'Loan application submitted successfully' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});
// Contact endpoint
app.post('/contact', verifyToken, async (req, res) => {
    const { message } = req.body;
    const username = req.user.username;

    if (!message) {
        return res.status(400).send({ success: false, message: 'Message is required' });
    }

    try {
        const newMessage = new Feedback({ message, username });
        await newMessage.save();
        res.status(201).send({ success: true, message: 'Message sent successfully' });
    } catch (error) {
        res.status(500).send({ success: false, message: 'Server error' });
    }
});

// Endpoint to fetch user-specific transactions
app.get('/user/transactions', verifyToken, async (req, res) => {
    try {
        const transactions = await ApprovedTransaction.find({ username: req.user.username }).sort({ date: -1 });
        console.log('Fetched transactions:', transactions); // Debug log
        res.json({ success: true, transactions });
    } catch (error) {
        console.error('Error fetching transactions:', error);
        res.status(500).json({ success: false, message: 'Error fetching transactions', error: error.message });
    }
});

// Add chat message
app.post('/chat', verifyToken, async (req, res) => {
    const { message, recipient } = req.body;

    try {
        const chatMessage = new ChatMessage({ username: req.user.username, message, recipient });
        await chatMessage.save();
        res.status(201).json({ success: true, message: 'Message sent successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error sending message', error });
    }
});

// Get Chat Messages Endpoint
app.post('/chat', verifyToken, async (req, res) => {
    const { message } = req.body;

    try {
        const chatMessage = new ChatMessage({ username: req.user.username, message });
        await chatMessage.save();
        res.status(201).json({ success: true, message: 'Message sent successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error sending message', error });
    }
});

app.get('/chat', verifyToken, async (req, res) => {
    try {
        const messages = await ChatMessage.find().sort({ time: -1 }).limit(50);
        res.status(200).json(messages);
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching messages', error });
    }
});

app.put('/chat/:id', verifyToken, async (req, res) => {
    const messageId = req.params.id;
    const { message } = req.body;

    try {
        const chatMessage = await ChatMessage.findById(messageId);

        if (!chatMessage) {
            return res.status(404).json({ success: false, message: 'Message not found' });
        }

        if (chatMessage.username !== req.user.username) {
            return res.status(403).json({ success: false, message: 'You are not authorized to edit this message' });
        }

        chatMessage.message = message;
        await chatMessage.save();

        res.json({ success: true, message: 'Message updated successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error updating message', error });
    }
});

app.delete('/chat/:id', verifyToken, async (req, res) => {
    const messageId = req.params.id;

    try {
        const message = await ChatMessage.findById(messageId);

        if (!message) {
            return res.status(404).json({ success: false, message: 'Message not found' });
        }

        if (message.username !== req.user.username) {
            return res.status(403).json({ success: false, message: 'You are not authorized to delete this message' });
        }

        await ChatMessage.deleteOne({ _id: messageId });
        res.json({ success: true, message: 'Message deleted successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error deleting message', error });
    }
});

// Send private message
app.post('/chat/private', verifyToken, async (req, res) => {
    const { recipient, message } = req.body;
    const sender = req.user.username;

    try {
        const chatMessage = new ChatMessage({ 
            username: sender, 
            message, 
            recipient,
            isPrivate: true 
        });
        await chatMessage.save();
        res.status(201).json({ success: true, message: 'Private message sent' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error sending private message', error });
    }
});


// Get private messages
app.get('/chat/private', verifyToken, async (req, res) => {
    const username = req.user.username;
    const recipient = req.query.recipient;
    try {
        const messages = await ChatMessage.find({
            $or: [
                { username: username, recipient: recipient, isPrivate: true },
                { username: recipient, recipient: username, isPrivate: true }
            ]
        }).sort({ time: -1 }).limit(50);
        res.status(200).json(messages);
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching private messages', error });
    }
});

// Admin registration endpoint
app.post('/register-admin', async (req, res) => {
    const { username, password } = req.body;

    try {
        const existingAdmin = await Admin.findOne({ username });
        if (existingAdmin) {
            return res.status(400).json({ message: 'Admin username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newAdmin = new Admin({
            username,
            password: hashedPassword,
        });

        await newAdmin.save();
        res.status(201).json({ message: 'Admin registered successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error registering admin', error });
    }
});

app.get('/admin/deposits', verifyToken, checkAdmin, async (req, res) => {
    try {
        const deposits = await Deposit.find();
        res.json({ success: true, deposits });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching deposits', error });
    }
});

module.exports = app;

app.post('/admin/deposits/:id/approve', verifyToken, checkAdmin, async (req, res) => {
    try {
        const deposit = await Deposit.findById(req.params.id);
        if (!deposit) {
            return res.status(404).json({ success: false, message: 'Deposit not found' });
        }

        // Update deposit status
        deposit.status = 'approved';
        await deposit.save();

        // Create new approved transaction
        const approvedTransaction = new ApprovedTransaction({
            username: deposit.username,
            type: 'deposit',
            amount: deposit.amount
        });
        await approvedTransaction.save();

        res.json({ success: true, message: 'Deposit approved successfully' });
    } catch (error) {
        console.error('Error approving deposit:', error);
        res.status(500).json({ success: false, message: 'Error approving deposit', error: error.message });
    }
});

app.post('/admin/deposits/:id/reject', verifyToken, checkAdmin, async (req, res) => {
    try {
        const deposit = await Deposit.findById(req.params.id);
        if (!deposit) {
            return res.status(404).json({ success: false, message: 'Deposit not found' });
        }

        // Update deposit status
        deposit.status = 'rejected';
        await deposit.save();

        res.json({ success: true, message: 'Deposit rejected successfully' });
    } catch (error) {
        console.error('Error rejecting deposit:', error);
        res.status(500).json({ success: false, message: 'Error rejecting deposit', error: error.message });
    }
});

app.get('/user/balance', verifyToken, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.user.username });
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        res.json({ success: true, balance: user.balance, shares: user.shares });
    } catch (error) {
        console.error('Error fetching balance:', error);
        res.status(500).json({ success: false, message: 'Error fetching balance', error: error.message });
    }
});

app.get('/user/transactions', verifyToken, async (req, res) => {
    try {
        const transactions = await ApprovedTransaction.find({ username: req.user.username }).sort({ date: -1 });
        res.json({ success: true, transactions });
    } catch (error) {
        console.error('Error fetching transactions:', error);
        res.status(500).json({ success: false, message: 'Error fetching transactions', error: error.message });
    }
});

app.get('/users', verifyToken, async (req, res) => {
    try {
        const users = await User.find({}, 'username');
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching users', error: error.message });
    }
});
//automatic recording of deposits
// Generate STK Push request
async function initiateMpesaStkPush(phoneNumber, amount) {
    try{
    const shortCode = '174379';
    const passkey = 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919';
    const timestamp = new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14);
    const password = Buffer.from(shortCode + passkey + timestamp).toString('base64');

 
       // Rest of your code remains same, but add these console logs
       console.log('Sending request with phone:', phoneNumber);
       console.log('Current timestamp:', timestamp);

    const parsedAmount = parseInt(amount);
        if (isNaN(parsedAmount) || parsedAmount <= 0) {
            throw new Error('Invalid amount');
        }

    const requestData = {
        BusinessShortCode: shortCode,
        Password: password,
        Timestamp: timestamp,
        TransactionType: "CustomerPayBillOnline",
        Amount: amount,
        PartyA: phoneNumber,
        PartyB: shortCode,
        PhoneNumber: phoneNumber,
        CallBackURL: 'https://6395-105-163-0-209.ngrok-free.app/api/mpesa/callback',
        AccountReference: "Account",
        TransactionDesc: "Deposit"
    };

    const mpesaAccessToken = await getOAuthToken();

    const response = await axios.post(
        'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
        requestData,
        {
            headers: { Authorization: `Bearer ${mpesaAccessToken}` }
        }
    );
    return response.data;
} catch (error) {
    console.error('STK push error:', error.response?.data || error);
    throw error;
}
}

async function initiateMpesaStkPushWithRetry(phoneNumber, amount, retries = 3) {
    for (let i = 0; i < retries; i++) {
        try {
            console.log(`Attempt ${i + 1} of ${retries}`);
            const result = await initiateMpesaStkPush(phoneNumber, amount);
            return result;
        } catch (error) {
            if (i === retries - 1) throw error;
            console.log(`Retrying after error: ${error.message}`);
            await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds between retries
        }
    }
}

// M-Pesa Callback Handler

// M-Pesa Callback Handler
app.post('/api/mpesa/callback', async (req, res) => {
    try {
        console.log('Callback received:', req.body);

        const stkCallback = req.body?.Body?.stkCallback;
        if (!stkCallback) {
            return res.status(400).send('Invalid callback payload');
        }

        const { ResultCode, CallbackMetadata } = stkCallback;
        if (ResultCode !== 0) {
            console.error('Transaction failed:', stkCallback.ResultDesc);
            return res.status(200).send('Transaction failed');
        }

        // Extract metadata
        const phoneNumber = CallbackMetadata.Item.find(i => i.Name === 'PhoneNumber').Value;
        const amount = CallbackMetadata.Item.find(i => i.Name === 'Amount').Value;
        const receiptNumber = CallbackMetadata.Item.find(i => i.Name === 'MpesaReceiptNumber').Value;

        // Match and update the deposit
        const deposit = await Deposit.findOne({ phoneNumber, status: 'pending' });
        if (!deposit) {
            console.error('No matching deposit found for phone:', phoneNumber);
            return res.status(404).send('No matching deposit found');
        }

        deposit.status = 'approved';
        deposit.amount = amount;
        deposit.mpesaMessage = receiptNumber;
        await deposit.save();

        // Update user balance
        const user = await User.findOne({ username: deposit.username });
        if (user) {
            user.balance += amount;
            await user.save();
        }

        console.log('Deposit updated successfully:', deposit);
        res.status(200).send('Callback processed successfully');
    } catch (error) {
        console.error('Error processing callback:', error);
        res.status(500).send('Server error');
    }
});

// Helper functions for deposit handling
async function handleSuccessfulDeposit(deposit) {
    // Update deposit status
    deposit.status = 'success';
    await deposit.save();

    // Update user balance
    const user = deposit.user;
    user.accountBalance += deposit.amount;
    await user.save();

    // Create transaction record
    await Transaction.create({
        user: user._id,
        type: 'deposit',
        amount: deposit.amount,
        status: 'completed',
        description: 'M-Pesa Deposit'
    });

    // Optional: Send notification
    await sendDepositNotification(user, deposit.amount);
}

async function handleTimeoutDeposit(deposit) {
    deposit.status = 'timeout';
    await deposit.save();

    // Optional: Retry mechanism or notify user
    await sendTimeoutNotification(deposit.user);
}

async function handleFailedDeposit(deposit, reason) {
    deposit.status = 'failed';
    await deposit.save();

    // Create failed transaction record
    await Transaction.create({
        user: deposit.user._id,
        type: 'deposit',
        amount: deposit.amount,
        status: 'failed',
        description: `M-Pesa Deposit Failed: ${reason}`
    });

    // Optional: Send failure notification
    await sendDepositFailureNotification(deposit.user, reason);
}
// OAuth token generation
async function getOAuthToken() {
    const auth = Buffer.from(`${consumerKey}:${consumerSecret}`).toString('base64');
    const response = await axios.get(
        'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
        { headers: { Authorization: `Basic ${auth}` } }
    );
    return response.data.access_token;
}

// Shares route
app.post('/shares/buy', verifyToken, async (req, res) => {
    try {
        const { amount, paymentMethod } = req.body;
        const username = req.user.username;
        
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const totalCost = amount * 100; // Assuming 100 shillings per share

        if (paymentMethod === 'deposited') {
            if (user.balance < totalCost) {
                return res.status(400).json({ success: false, message: 'Insufficient funds' });
            }

            // Deduct the amount from the user's account
            user.balance -= totalCost;
            user.shares += parseInt(amount);
            await user.save();

            // Create a new share purchase record
            const newShare = new Share({
                username: user.username,
                amount: parseInt(amount),
                cost: totalCost,
                paymentMethod: 'deposited'
            });
            await newShare.save();

            const newTransaction = new ApprovedTransaction({
                username: user.username,
                type: 'buy shares',
                amount: totalCost,
                paymentMethod: 'deposited'
            });
            await newTransaction.save();
console.log('New transaction saved:', newTransaction);
            return res.json({ 
                success: true, 
                message: `Successfully purchased ${amount} shares`, 
                newBalance: user.balance,
                newShares: user.shares

                
            });
        } else if (paymentMethod === 'deposited') {
            if (user.balance < totalCost) {
                return res.status(400).json({ success: false, message: 'Insufficient funds' });
            }

            // Deduct the amount from the user's account
            user.balance -= totalCost;
            user.shares += parseInt(amount);
            await user.save();

            // Create a new share purchase record
            const newShare = new Share({
                username: user.username,
                amount: parseInt(amount),
                cost: totalCost,
                paymentMethod: 'deposited'
            });
            await newShare.save();

            // Create a new approved transaction
            
            return res.json({ success: true, message: `Successfully purchased ${amount} shares`, newBalance: user.balance });
        }

        return res.json({ 
            success: true, 
            message: `Successfully purchased ${amount} shares via M-Pesa`, 
            newShares: user.shares
        });
    
    res.status(400).json({ success: false, message: 'Invalid payment method' });
    } catch (error) {
        console.error('Error in /shares/buy:', error);
        res.status(500).json({ success: false, message: 'Server error', error: error.message });
    }
     // Create a new approved transaction
     const newTransaction = new ApprovedTransaction({
        username: user.username,
        type: 'buy shares',
        amount: totalCost
    });
    await newTransaction.save();
});
  module.exports = router;
  app.post('/shares/buy-pending', verifyToken, async (req, res) => {
    const { amount, mpesaMessage, username } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Create a pending share purchase
        const pendingPurchase = new PendingSharePurchase({
            username,
            amount: parseInt(amount),
            mpesaMessage,
            status: 'pending'
        });
        await pendingPurchase.save();

        res.json({ success: true, message: 'Share purchase request submitted for approval' });
    } catch (error) {
        console.error('Error in /shares/buy-pending:', error);
        res.status(500).json({ success: false, message: 'Server error', error: error.message });
    }
});

app.get('/chat/private', verifyToken, async (req, res) => {
    const username = req.user.username;
    try {
        const messages = await ChatMessage.find({
            $or: [
                { username: username, recipient: { $ne: 'all' }, isPrivate: true },
                { recipient: username, isPrivate: true }
            ]
        }).sort({ time: -1 }).limit(50);
        res.status(200).json(messages);
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching private messages', error });
    }
});

app.get('/user/transaction-history', verifyToken, async (req, res) => {
    try {
        const transactions = await ApprovedTransaction.find({ username: req.user.username })
            .sort({ date: -1 });

        console.log('Fetched transactions:', transactions); // Add this for debugging

        const labels = transactions.map(t => t.date.toISOString());
        const data = transactions.map(t => t.amount);
        const types = transactions.map(t => t.type);

        res.json({ success: true, labels, data, types });
    } catch (error) {
        console.error('Error fetching transaction history:', error);
        res.status(500).json({ success: false, message: 'Error fetching transaction history', error: error.message });
    }
});

app.post('/sync-balance', verifyToken, async (req, res) => {
    try {
        const transactions = await ApprovedTransaction.find({ username: req.user.username });
        let balance = 0;

        for (let transaction of transactions) {
            switch(transaction.type) {
                case 'deposit':
                    balance += transaction.amount;
                    break;
                case 'withdrawal':
                case 'buy shares':
                    if (transaction.paymentMethod === 'deposited') {
                        balance -= transaction.amount;
                    }
                    break;
                // Add other transaction types as needed
            }
        }

        await User.findOneAndUpdate({ username: req.user.username }, { balance: balance });

        res.json({ success: true, message: 'Balance synced successfully', newBalance: balance });
    } catch (error) {
        console.error('Error syncing balance:', error);
        res.status(500).json({ success: false, message: 'Error syncing balance', error: error.message });
    }
});
async function getUserBalance(username) {
    const user = await User.findOne({ username });
    if (!user) {
        throw new Error('User not found');
    }
    return user.balance;
}

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ success: false, message: 'Server error', error: err.message });
});
app.post('/api/mpesa/callback', async (req, res) => {
    try {
        const { Body: { stkCallback } = {} } = req.body;

        if (!stkCallback) {
            console.error('Invalid callback payload:', req.body);
            return res.status(400).send('Invalid payload');
        }

        const { CheckoutRequestID, ResultCode, ResultDesc } = stkCallback;

        if (ResultCode !== 0) {
            console.error('Transaction failed:', ResultDesc);
            return res.status(200).send('Transaction failed');
        }

        // Find deposit by CheckoutRequestID
        const deposit = await Deposit.findOne({ mpesaMessage: CheckoutRequestID, status: 'pending' });
        if (!deposit) {
            console.error('No matching deposit found for:', CheckoutRequestID);
            return res.status(404).send('No matching deposit found');
        }

        // Update deposit and user balance
        const amount = stkCallback.CallbackMetadata.Item.find(i => i.Name === 'Amount').Value;
        deposit.status = 'approved';
        deposit.amount = amount;
        await deposit.save();

        const user = await User.findOne({ username: deposit.username });
        if (user) {
            user.balance += amount;
            await user.save();
        }

        res.status(200).send('Callback processed successfully');
    } catch (error) {
        console.error('Error in callback:', error);
        res.status(500).send('Server error');
    }
});


// Get all withdraw requests
app.get('/admin/withdrawals', verifyToken, checkAdmin, async (req, res) => {
    try {
        const withdrawals = await Withdraw.find();
        res.json({ success: true, withdrawals });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching withdrawals' });
    }
});

app.post('/admin/withdrawals/:id/:status', verifyToken, checkAdmin, async (req, res) => {
    const { id, status } = req.params;
    
    try {
        const withdrawal = await Withdraw.findById(id);
        if (!withdrawal) {
            return res.status(404).json({ success: false, message: 'Withdrawal not found' });
        }

        withdrawal.status = status;
        await withdrawal.save();

        if (status === 'completed') {
            const user = await User.findOne({ username: withdrawal.username });
            if (user) {
                user.balance -= withdrawal.amount;
                await user.save();

                const newTransaction = new ApprovedTransaction({
                    username: withdrawal.username,
                    type: 'withdrawal',
                    amount: withdrawal.amount
                });
                await newTransaction.save();
            }
        }

        res.json({ success: true, message: `Withdrawal ${status} successfully` });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error updating withdrawal status' });
    }
});

// Reject a withdraw request
app.post('/admin/withdraws/:id/reject', verifyToken, checkAdmin, async (req, res) => {
    try {
        const withdraw = await Withdraw.findById(req.params.id);
        if (!withdraw) {
            return res.status(404).json({ success: false, message: 'Withdraw not found' });
        }

        // Update withdraw status
        withdraw.status = 'rejected';
        await withdraw.save();

        res.json({ success: true, message: 'Withdraw rejected successfully' });
    } catch (error) {
        console.error('Error rejecting withdraw:', error);
        res.status(500).json({ success: false, message: 'Error rejecting withdraw', error: error.message });
    }
});

app.post('/admin/process-withdrawal', verifyToken, checkAdmin, async (req, res) => {
    const { withdrawalId, amount, phoneNumber } = req.body;

    try {
        // Validate the withdrawal request
        const withdrawal = await Withdraw.findById(withdrawalId);
        if (!withdrawal || withdrawal.status !== 'pending') {
            return res.status(400).json({ success: false, message: 'Invalid withdrawal request' });
        }

        // Process the M-Pesa transaction
        const mpesaResult = await processMpesaTransaction(phoneNumber, amount);

        if (mpesaResult.success) {
            // Update withdrawal status
            withdrawal.status = 'completed';
            await withdrawal.save();

            // Update user's balance
            const user = await User.findOne({ username: withdrawal.username });
            user.balance -= amount;
            await user.save();

            // Create a new transaction record
            const newTransaction = new ApprovedTransaction({
                username: withdrawal.username,
                type: 'withdrawal',
                amount: amount
            });
            await newTransaction.save();

            res.json({ success: true, message: 'Withdrawal processed successfully' });
        } else {
            res.status(400).json({ success: false, message: 'M-Pesa transaction failed' });
        }
    } catch (error) {
        console.error('Error processing withdrawal:', error);
        res.status(500).json({ success: false, message: 'Error processing withdrawal' });
    }
});

// Get all loan requests
app.get('/admin/loan-requests', verifyToken, checkAdmin, async (req, res) => {
    try {
        const loanRequests = await LoanRequest.find();
        res.json({ success: true, loanRequests });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching loan requests' });
    }
});

// Approve or reject a loan request
app.post('/admin/loan-requests/:id/:action', verifyToken, checkAdmin, async (req, res) => {
    const { id, action } = req.params;
    
    try {
        const loanRequest = await LoanRequest.findById(id);
        if (!loanRequest) {
            return res.status(404).json({ success: false, message: 'Loan request not found' });
        }

        const user = await User.findOne({ username: loanRequest.username });
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        if (action === 'approve') {
            // Update user's balance
            user.balance += loanRequest.amount;
            await user.save();

            // Create a new transaction record
            const newTransaction = new ApprovedTransaction({
                username: loanRequest.username,
                type: 'loan',
                amount: loanRequest.amount
            });
            await newTransaction.save();

            res.json({ success: true, message: 'Loan approved successfully', phoneNumber: user.phoneNumber });
        } else if (action === 'reject') {
            res.json({ success: true, message: 'Loan rejected successfully' });
        } else {
            res.status(400).json({ success: false, message: 'Invalid action' });
        }
        const newTransaction = new ApprovedTransaction({
            username: loanRequest.username,
            type: 'loan',
            amount: loanRequest.amount
        });
        await newTransaction.save();

        // Remove the loan request
        await LoanRequest.findByIdAndDelete(id);
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error processing loan request' });
    }
});
app.get('/user/messages', verifyToken, async (req, res) => {
    try {
        const messages = await Feedback.find({ username: req.user.username }).sort({ time: -1 });
        res.json({ success: true, messages });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching messages', error: error.message });
    }
});
app.get('/admin/messages', verifyToken, checkAdmin, async (req, res) => {
    try {
        const messages = await Feedback.find().sort({ time: -1 });
        res.json({ success: true, messages });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching messages', error: error.message });
    }
});

app.post('/admin/messages/:id/read', verifyToken, checkAdmin, async (req, res) => {
    try {
        const message = await Feedback.findByIdAndUpdate(req.params.id, { read: true }, { new: true });
        if (!message) {
            return res.status(404).json({ success: false, message: 'Message not found' });
        }
        res.json({ success: true, message: 'Message marked as read' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error marking message as read', error: error.message });
    }
});

app.post('/exit-sacco', verifyToken, async (req, res) => {
    try {
        const { username } = req.body;
        const user = await User.findOne({ username });
        
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Check for outstanding loans
        const outstandingLoan = await LoanRequest.findOne({ username: user.username, status: 'approved' });
        
        // Calculate share value
        const shareValue = user.shares * 100; // Assuming 100 per share

        let exitStatus = 'pending';
        let exitMessage = '';

        if (outstandingLoan) {
            exitStatus = 'loan_outstanding';
            exitMessage = 'You have an outstanding loan. Please clear it or have your guarantor clear it before exiting.';
        } else if (user.balance > 0 || user.shares > 0) {
            exitStatus = 'refund_pending';
            exitMessage = 'Your exit request has been submitted. An admin will process your final refund.';
        } else {
            exitStatus = 'completed';
            exitMessage = 'Your account has been successfully closed.';
            await User.findOneAndDelete({ username: user.username });
        }

        // Create exit notification
        const exitNotification = new ExitNotification({
            username: user.username,
            userData: {
                ...user.toObject(),
                exitBalance: user.balance,
                exitShares: user.shares,
                exitShareValue: shareValue,
                totalExitValue: user.balance + shareValue,
                phoneNumber: user.phoneNumber
            },
            status: exitStatus
        });
        await exitNotification.save();

        res.json({ 
            success: true, 
            message: exitMessage,
            exitDetails: {
                balance: user.balance,
                shares: user.shares,
                shareValue: shareValue,
                totalValue: user.balance + shareValue,
                status: exitStatus
            }
        });
    } catch (error) {
        console.error('Error during sacco exit:', error);
        res.status(500).json({ success: false, message: 'An error occurred during the exit process' });
    }
});

// Admin get all exit notifications
app.get('/admin/exit-notifications', verifyToken, checkAdmin, async (req, res) => {
    try {
        const exitNotifications = await ExitNotification.find().sort({ exitDate: -1 });
        res.json({ success: true, exitNotifications });
    } catch (error) {
        console.error('Error fetching exit notifications:', error);
        res.status(500).json({ success: false, message: 'Error fetching exit notifications' });
    }
});

// Admin reinstate user
app.post('/admin/reinstate-user/:id', verifyToken, checkAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const exitNotification = await ExitNotification.findById(id);
        if (!exitNotification) {
            return res.status(404).json({ success: false, message: 'Exit notification not found' });
        }

        // Recreate user account
        const newUser = new User(exitNotification.userData);
        await newUser.save();

        // Remove exit notification
        await ExitNotification.findByIdAndDelete(id);

        res.json({ success: true, message: 'User has been reinstated successfully' });
    } catch (error) {
        console.error('Error reinstating user:', error);
        res.status(500).json({ success: false, message: 'Error reinstating user' });
    }
});

app.get('/admin/exit-requests', verifyToken, checkAdmin, async (req, res) => {
    try {
        const exitRequests = await ExitNotification.find({ status: { $ne: 'completed' } });
        res.json({ success: true, exitRequests });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error fetching exit requests' });
    }
});

app.post('/admin/process-exit/:id', verifyToken, checkAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { action } = req.body; // 'refund' or 'delete'

        const exitNotification = await ExitNotification.findById(id);
        if (!exitNotification) {
            return res.status(404).json({ success: false, message: 'Exit request not found' });
        }

        const user = await User.findOne({ username: exitNotification.username });

        if (action === 'refund') {
            // Process refund logic here
            // This is where you'd integrate with your payment system
            console.log(`Refund processed for user ${exitNotification.username}`);
            
            exitNotification.status = 'refunded';
            await exitNotification.save();

            if (user) {
                user.balance = 0;
                user.shares = 0;
                await user.save();
            }

            return res.json({ success: true, message: 'Refund processed successfully' });
        } else if (action === 'delete') {
            if (user) {
                await User.findOneAndDelete({ username: exitNotification.username });
            }
            exitNotification.status = 'completed';
            await exitNotification.save();

            return res.json({ success: true, message: 'User account deleted successfully' });
        } else {
            return res.status(400).json({ success: false, message: 'Invalid action' });
        }
    } catch (error) {
        console.error('Error processing exit request:', error);
        res.status(500).json({ success: false, message: 'Error processing exit request' });
    }
});


async function checkAndCreateNotifications() {
    const currentDate = new Date();
    const mgrs = await MGR.find({});
  
    for (const mgr of mgrs) {
      const currentMonth = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1);
      const scheduleEntry = mgr.schedule.find(entry => 
        new Date(entry.month).getTime() === currentMonth.getTime()
      );
  
      if (scheduleEntry) {
        // Notify the recipient
        await createNotification(
          scheduleEntry.recipient,
          `You are the recipient for ${mgr.name} this month.`,
          'recipient_selected'
        );
  
        // Notify other participants to make payments
        for (const participant of mgr.participants) {
          if (participant !== scheduleEntry.recipient) {
            await createNotification(
              participant,
              `It's time to make your payment for ${mgr.name}. The recipient is ${scheduleEntry.recipient}.`,
              'payment_due'
            );
          }
        }
      }
  
      // Check for upcoming MGR start
      const oneWeekFromNow = new Date(currentDate.getTime() + 7 * 24 * 60 * 60 * 1000);
      if (mgr.startDate > currentDate && mgr.startDate <= oneWeekFromNow) {
        for (const participant of mgr.participants) {
          await createNotification(
            participant,
            `The Merry-Go-Round "${mgr.name}" will start in a week.`,
            'mgr_starting_soon'
          );
        }
      }
    }
  }

  app.get('/mgr/notifications', verifyToken, async (req, res) => {
    try {
      console.log('Fetching notifications for user:', req.user.username);
      
      if (!req.user || !req.user.username) {
        return res.status(400).json({ success: false, message: 'User not properly authenticated' });
      }
  
      await checkAndCreateNotifications();
      console.log('Checked and created notifications');
  
      const notifications = await Notification.find({ username: req.user.username, read: false })
        .sort({ createdAt: -1 })
        .limit(10);
      console.log('Found notifications:', notifications);
  
      res.json({ success: true, notifications });
    } catch (error) {
      console.error('Error in /mgr/notifications:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Error fetching notifications', 
        error: error.message,
        stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
      });
    }
  });
  
  // Endpoint to mark a notification as read
  app.post('/mgr/notifications/read', verifyToken, async (req, res) => {
    try {
      const { notificationId } = req.body;
      await Notification.findByIdAndUpdate(notificationId, { read: true });
      res.json({ success: true, message: 'Notification marked as read' });
    } catch (error) {
      console.error('Error marking notification as read:', error);
      res.status(500).json({ success: false, message: 'Error marking notification as read' });
    }
  });


app.get('/mgr/list', verifyToken, async (req, res) => {
    console.log('MGR list route hit');
    try {
      const mgrs = await MGR.find().lean();
      console.log('MGRs found:', mgrs);
      res.json({ success: true, mgrs });
    } catch (error) {
      console.error('Error in /mgr/list:', error);
      res.status(500).json({ success: false, message: 'Error fetching MGR list', error: error.toString() });
    }
  });
  
  app.get('/mgr/details/:id', verifyToken, async (req, res) => {
    try {
      const mgr = await MGR.findById(req.params.id).lean();
      if (!mgr) {
        return res.status(404).json({ success: false, message: 'MGR not found' });
      }
      res.json({ success: true, mgr });
    } catch (error) {
      console.error('Error in /mgr/details:', error);
      res.status(500).json({ success: false, message: 'Error fetching MGR details', error: error.toString() });
    }
  });
  
  app.post('/mgr/join', verifyToken, async (req, res) => {
    try {
      const { mgrId } = req.body;
      const mgr = await MGR.findById(mgrId);
      if (!mgr) {
        return res.status(404).json({ success: false, message: 'MGR not found' });
      }
      if (!mgr.participants.includes(req.user.username)) {
        mgr.participants.push(req.user.username);
        await mgr.save();
      }
      res.json({ success: true, message: 'Joined MGR successfully' });
    } catch (error) {
      console.error('Error in /mgr/join:', error);
      res.status(500).json({ success: false, message: 'Error joining MGR', error: error.toString() });
    }
  });
  
  app.post('/mgr/create', verifyToken, async (req, res) => {
    console.log('User from token:', req.user);
    try {
        const { name, monthlyAmount, startDate, participants } = req.body;
        const validParticipants = [req.user.username, ...participants].filter(p => p != null);
        
        const newMGR = new MGR({
            name,
            participants: validParticipants,
            monthlyAmount,
            startDate: new Date(startDate),
            schedule: []
        });
        const savedMGR = await newMGR.save();
        res.json({ success: true, message: 'MGR created successfully', mgr: savedMGR });
    } catch (error) {
        console.error('Error in /mgr/create:', error);
        res.status(500).json({ success: false, message: 'Error creating MGR', error: error.toString() });
    }
});

  app.post('/mgr/pick-recipient', verifyToken, async (req, res) => {
    try {
        const username = req.user.username;
        // Find MGR where the user is a participant (not necessarily the first one)
        const mgr = await MGR.findOne({ participants: username });
        
        if (!mgr) {
            return res.status(404).json({ success: false, message: 'MGR not found or you are not a participant' });
        }

        // Check if the user is the creator (first participant)
        if (mgr.participants[0] !== username) {
            return res.status(403).json({ success: false, message: 'Only the creator can pick a recipient' });
        }

        // Rest of the logic to pick a new recipient
        const participants = mgr.participants;
        const eligibleParticipants = participants.filter(participant => 
            !mgr.schedule.some(entry => entry.recipient === participant)
        );
        const recipientPool = eligibleParticipants.length > 0 ? eligibleParticipants : participants;
        const recipient = recipientPool[Math.floor(Math.random() * recipientPool.length)];

        const user = await User.findOne({ username: recipient });
        if (!user) {
            return res.status(404).json({ success: false, message: 'Recipient not found' });
        }

        const newScheduleEntry = {
            month: currentMonth,
            recipient: recipient,
            payments: []
        };

        mgr.schedule.push(newScheduleEntry);
        await mgr.save();

        res.json({ success: true, recipient, phoneNumber: user.phoneNumber });
    } catch (error) {
        console.error('Error in /mgr/pick-recipient:', error);
        res.status(500).json({ success: false, message: 'Error picking recipient', error: error.toString() });
    }
});

// M-Pesa API credentials
const consumerKey = process.env.MPESA_CONSUMER_KEY;
const consumerSecret = process.env.MPESA_CONSUMER_SECRET;

// Helper function to get OAuth token
async function getOAuthToken() {
  const auth = Buffer.from(`${consumerKey}:${consumerSecret}`).toString('base64');
  try {
    const response = await axios.get('https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials', {
      headers: {
        Authorization: `Basic ${auth}`,
      },
    });
    return response.data.access_token;
  } catch (error) {
    console.error('Error getting OAuth token:', error);
    throw error;
  }
}

app.post('/api/mpesa/callback', (req, res) => {
    console.log('Callback received:', req.body);

    const { Body } = req.body;

    if (Body && Body.stkCallback) {
        const { MerchantRequestID, CheckoutRequestID, ResultCode, ResultDesc } = Body.stkCallback;

        console.log('ResultCode:', ResultCode);
        console.log('ResultDesc:', ResultDesc);

        // Save the transaction status to the database
    }

    res.status(200).send('Callback received successfully');
});

// Serve HTML pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/deposits', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'deposits.html'));
});

app.get('/withdraw', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'withdraw.html'));
});

app.get('/apply-loan', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'apply-loan.html'));
});

app.get('/chat', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});

app.get('/transactions', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'transactions.html'));
});
app.get('/protected', verifyToken, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.userId, isAdmin: req.isAdmin });
});
app.get('/test', verifyToken, (req, res) => {
    res.json({ success: true, user: req.user });
});

app.get('/mgr/details', (req, res) => {
    // Fetch MGR details from database
    res.json({ success: true, mgr: { /* MGR details */ } });
});

app.get('/mgr/list', (req, res) => {
    // Fetch list of MGRs from database
    res.json({ success: true, mgrs: [ /* list of MGRs */ ] });
});

app.post('/mgr/create', (req, res) => {
    // Create new MGR in database
    res.json({ success: true, message: 'MGR created successfully' });
});

app.post('/mgr/join', (req, res) => {
    // Add user to MGR in database
    res.json({ success: true, message: 'Joined MGR successfully' });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
