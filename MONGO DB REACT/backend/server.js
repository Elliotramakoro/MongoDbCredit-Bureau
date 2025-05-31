require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// ========== SCHEMAS ========== //
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['borrower', 'lender', 'admin'], required: true }
});
const User = mongoose.model('User', UserSchema);

const LoanOfferSchema = new mongoose.Schema({
  lenderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  interestRate: { type: Number, required: true },
  maxTermMonths: { type: Number, required: true },
  isActive: { type: Boolean, default: true }
});
const LoanOffer = mongoose.model('LoanOffer', LoanOfferSchema);

const LoanApplicationSchema = new mongoose.Schema({
  borrowerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  loanOfferId: { type: mongoose.Schema.Types.ObjectId, ref: 'LoanOffer', required: true },
  nationalId: { type: String, required: true },
  monthlySalary: { type: Number, required: true },
  reason: { type: String, required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' }
});
const LoanApplication = mongoose.model('LoanApplication', LoanApplicationSchema);

const LoanPaymentSchema = new mongoose.Schema({
  applicationId: { type: mongoose.Schema.Types.ObjectId, ref: 'LoanApplication', required: true },
  amountPaid: { type: Number, default: 0 },
  payments: [
    {
      date: { type: Date, default: Date.now },
      amount: Number
    }
  ]
});
const LoanPayment = mongoose.model('LoanPayment', LoanPaymentSchema);

// ========== AUTHENTICATION MIDDLEWARE ========== //
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ========== AUTH ROUTES ========== //
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: 'All fields are required!' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered!' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword, role });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully!' });
  } catch (err) {
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password, role } = req.body;
    const user = await User.findOne({ email, role });
    if (!user) return res.status(400).json({ error: 'Invalid email or role!' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).json({ error: 'Invalid password!' });

    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ 
      message: 'Login successful!',
      token,
      user: { name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// Lender Routes
app.post('/api/lender/loan-offers', authenticate, async (req, res) => {
  if (req.user.role !== 'lender') return res.status(403).json({ error: 'Forbidden' });

  try {
    const { amount, interestRate, maxTermMonths } = req.body;
    const newOffer = new LoanOffer({
      lenderId: req.user.id,
      amount,
      interestRate,
      maxTermMonths
    });
    await newOffer.save();
    res.status(201).json(newOffer);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/lender/loan-offers', authenticate, async (req, res) => {
  if (req.user.role !== 'lender') return res.status(403).json({ error: 'Forbidden' });

  try {
    const offers = await LoanOffer.find({ lenderId: req.user.id });
    res.json(offers);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Single endpoint to get applications with payment info
app.get('/api/lender/applications', authenticate, async (req, res) => {
  if (req.user.role !== 'lender') return res.status(403).json({ error: 'Forbidden' });

  try {
    const offerIds = await LoanOffer.find({ lenderId: req.user.id }).select('_id');
    const applications = await LoanApplication.find({ loanOfferId: { $in: offerIds } })
      .populate('borrowerId', 'name email')
      .populate('loanOfferId', 'amount interestRate');

    // Fetch payment info for all applications
    const appIds = applications.map(app => app._id);
    const payments = await LoanPayment.find({ applicationId: { $in: appIds } });

    const paymentMap = {};
    payments.forEach(p => {
      paymentMap[p.applicationId.toString()] = {
        amountPaid: p.amountPaid,
        payments: p.payments
      };
    });

    // Attach payment info to each application
    const enrichedApps = applications.map(app => ({
      ...app.toObject(),
      paymentInfo: paymentMap[app._id.toString()] || null
    }));

    res.json(enrichedApps);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH endpoint to approve or reject a loan application
app.patch('/api/lender/applications/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'lender') return res.status(403).json({ error: 'Forbidden' });

  try {
    const { status } = req.body;
    const appToUpdate = await LoanApplication.findById(req.params.id).populate('loanOfferId');

    if (!appToUpdate) return res.status(404).json({ error: 'Application not found' });

    if (status === 'approved') {
      // Mark the offer as inactive when approved
      await LoanOffer.findByIdAndUpdate(appToUpdate.loanOfferId._id, { isActive: false });

      // Create LoanPayment record if not already created
      const existingPayment = await LoanPayment.findOne({ applicationId: req.params.id });
      if (!existingPayment) {
        await LoanPayment.create({ applicationId: req.params.id });
      }
    }

    // Update application status
    const updatedApp = await LoanApplication.findByIdAndUpdate(req.params.id, { status }, { new: true });
    res.json(updatedApp);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ========== BORROWER ROUTES ========== //
app.get('/api/borrower/loan-offers', authenticate, async (req, res) => {
  if (req.user.role !== 'borrower') return res.status(403).json({ error: 'Forbidden' });

  try {
    const offers = await LoanOffer.find({ isActive: true }).populate('lenderId', 'name');
    res.json(offers);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/borrower/applications', authenticate, async (req, res) => {
  if (req.user.role !== 'borrower') return res.status(403).json({ error: 'Forbidden' });

  try {
    const { loanOfferId, nationalId, monthlySalary, reason } = req.body;
    const newApp = new LoanApplication({
      borrowerId: req.user.id,
      loanOfferId,
      nationalId,
      monthlySalary,
      reason
    });
    await newApp.save();
    res.status(201).json(newApp);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/borrower/applications', authenticate, async (req, res) => {
  if (req.user.role !== 'borrower') return res.status(403).json({ error: 'Forbidden' });

  try {
    const applications = await LoanApplication.find({ borrowerId: req.user.id })
      .populate('loanOfferId', 'amount interestRate lenderId')
      .populate('loanOfferId.lenderId', 'name');
    res.json(applications);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== PAYMENT ROUTES ========== //
app.get('/api/borrower/payments', authenticate, async (req, res) => {
  if (req.user.role !== 'borrower') return res.status(403).json({ error: 'Forbidden' });

  try {
    const apps = await LoanApplication.find({ borrowerId: req.user.id }).select('_id loanOfferId').populate('loanOfferId');
    const appMap = Object.fromEntries(apps.map(app => [app._id.toString(), app.loanOfferId]));

    const payments = await LoanPayment.find({ applicationId: { $in: apps.map(a => a._id) } });

    const enriched = payments.map(p => ({
      ...p.toObject(),
      loanAmount: appMap[p.applicationId.toString()]?.amount || 0,
      interestRate: appMap[p.applicationId.toString()]?.interestRate || 0
    }));

    res.json(enriched);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.post('/api/borrower/payments/:applicationId', authenticate, async (req, res) => {
  if (req.user.role !== 'borrower') return res.status(403).json({ error: 'Forbidden' });

  try {
    const { amount } = req.body;
    const payment = await LoanPayment.findOneAndUpdate(
      { applicationId: req.params.applicationId },
      {
        $inc: { amountPaid: amount },
        $push: { payments: { amount } }
      },
      { new: true }
    );
    res.json(payment);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


//==============================================================================//
// ✅ ADMIN ROUTES FOR server.js
const calculateCreditScore = (borrower) => {
  let score = 700;
  if (borrower.payments && borrower.payments.length > 0) {
    const totalPayments = borrower.payments.reduce((sum, p) => sum + (p.payments?.length || 0), 0);
    score += totalPayments * 5;
  }
  if (borrower.applications && borrower.applications.length > 0) {
    const approvedLoans = borrower.applications.filter(a => a.status === 'approved').length;
    score += approvedLoans * 20;
  }
  return Math.min(Math.max(score, 300), 850);
};

// GET all users
app.get('/api/admin/users', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const users = await User.find({}, { password: 0 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET all borrowers with applications and payments
app.get('/api/admin/borrowers', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const borrowers = await User.find({ role: 'borrower' }, { password: 0 });
    const borrowerIds = borrowers.map(b => b._id);

    const applications = await LoanApplication.find({ borrowerId: { $in: borrowerIds } }).populate('loanOfferId');
    const payments = await LoanPayment.find({}).populate('applicationId');

    const data = borrowers.map(borrower => {
      const borrowerApps = applications.filter(a => a.borrowerId.toString() === borrower._id.toString());
      const borrowerPayments = payments.filter(p => 
        borrowerApps.some(a => a._id.toString() === p.applicationId?._id?.toString())
      );

      return {
        ...borrower.toObject(),
        applications: borrowerApps,
        payments: borrowerPayments,
        creditScore: calculateCreditScore({ applications: borrowerApps, payments: borrowerPayments })
      };
    });

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE user
app.delete('/api/admin/users/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    if (req.params.id === req.user.id) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH user role
app.patch('/api/admin/users/:id/role', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const { role } = req.body;
    const updated = await User.findByIdAndUpdate(req.params.id, { role }, { new: true }).select('-password');
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET all loan applications
app.get('/api/admin/loan-applications', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const apps = await LoanApplication.find()
      .populate('borrowerId', 'name email')
      .populate('loanOfferId')
      .populate('loanOfferId.lenderId', 'name');
    res.json(apps);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET all loan offers
app.get('/api/admin/loan-offers', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const offers = await LoanOffer.find().populate('lenderId', 'name email');
    res.json(offers);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET all payments
app.get('/api/admin/payments', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const payments = await LoanPayment.find()
      .populate({
        path: 'applicationId',
        populate: [
          { path: 'borrowerId', select: 'name email' },
          { path: 'loanOfferId', populate: { path: 'lenderId', select: 'name' } }
        ]
      });
    res.json(payments);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


//============THE GRAPHS HERE ==========//
// Add to borrower routes
app.get('/api/borrower/credit-score', authenticate, async (req, res) => {
  if (req.user.role !== 'borrower') return res.status(403).json({ error: 'Forbidden' });
  
  try {
    // Simplified scoring logic - replace with your actual algorithm
    const borrower = await User.findById(req.user.id)
      .populate('applications')
      .populate('payments');
    
    let score = 650; // Base score
    
    // Add points for on-time payments
    if (borrower.payments) {
      const onTimePayments = borrower.payments.filter(p => p.status === 'ontime').length;
      score += onTimePayments * 5;
    }
    
    // Deduct points for late payments
    if (borrower.payments) {
      const latePayments = borrower.payments.filter(p => p.status === 'late').length;
      score -= latePayments * 10;
    }
    
    // Ensure score stays within bounds
    score = Math.max(300, Math.min(score, 850));
    
    res.json({ score });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== START SERVER ========== //
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
