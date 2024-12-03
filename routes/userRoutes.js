const express = require('express');
const { createAccount } = require('../controllers/userController');
const { validateAccount } = require('../controllers/userController');
const { updatePassword } = require('../controllers/userController');
const { validateResetCode } = require('../controllers/userController');
const { forgotPassword } = require('../controllers/userController');  
const { login } = require('../controllers/userController');
const { logout } = require('../controllers/userController');
const { removeUser } = require('../controllers/userController');

const router = express.Router();

// Create Account
router.post('/create', createAccount);

// Validate Account
router.post('/validate', validateAccount);

// Update Password
router.post('/update-password', updatePassword);

//Login User
router.post('/login', login);

//Logout User
router.post('/logout', logout);

//Remove User
router.delete('/remove', removeUser);

//forgot password
router.post('/forgot-password', forgotPassword); 

//validate reset code
router.post('/validate-reset-code', validateResetCode); 

module.exports = router;
