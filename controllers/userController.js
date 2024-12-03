const bcrypt = require('bcryptjs');
const { successResponse, errorResponse } = require('../utils/responseHandler');
const nodemailer = require('nodemailer');


// Mock Database (replace with actual DB logic)
let users = [
  { email: 'testuser@example.com', password: '$2a$10$S4Lpgk1xqGpAnhn.X5x.d.Jg1eJ6hthm7tw4LVjQuftlg0mVS1B5O', verified: true } // Mock hashed password
];
let validAuthTokens = ['mockAuthToken123']; // For storing mock tokens
let resetCodes = {}; // Store reset codes for validation

exports.createAccount = async (req, res) => {
  console.log('I am under the createAccount');
  const { email, name, phone, city, state } = req.body;

  // Validate input
  if (!email || !name || !phone || !city || !state) {
    return errorResponse(res, 400, 'Missing required fields');
  }

  // Check if user already exists
  const existingUser = users.find((user) => user.email === email);
  if (existingUser) {
    return errorResponse(res, 409, 'Email already registered');
  }

  try {
    // Hash a mock password for now
    const hashedPassword = await bcrypt.hash('defaultpassword', 10);

    // Save user to mock database
    users.push({ email, name, phone, city, state, password: hashedPassword });

    return successResponse(res, 'Account created successfully. Verification code sent to email.', {
      code_sent: true,
    });
  } catch (error) {
    return errorResponse(res, 500, 'Internal Server Error', error.message);
  }
};

exports.validateAccount = (req, res) => {
  const { email, code } = req.body;

  // Validate input
  if (!email || !code) {
    return errorResponse(res, 400, 'Missing required fields');
  }

  // Mock database verification (Replace with actual DB in production)
  const user = users.find((user) => user.email === email);
  if (!user) {
    return errorResponse(res, 404, 'Email not found');
  }

  // Mock verification code logic (In production, check against a real code)
  const mockVerificationCode = '123456'; // Hardcoded for now
  if (code !== mockVerificationCode) {
    return errorResponse(res, 401, 'Incorrect verification code');
  }

  // Generate a mock auth token (In production, use a secure token)
  const authToken = 'mockAuthToken123'; // Replace with JWT logic

  return successResponse(res, 'Email verified successfully.', {
    auth_token: authToken,
  });
};

// Login Flow
exports.login = async (req, res) => {
  const { email, password } = req.body;

  // Validate input
  if (!email || !password) {
    return errorResponse(res, 400, 'Missing required fields: email or password');
  }

  // Simulate user lookup from the database
  const user = users.find(user => user.email === email);

  if (!user) {
    return errorResponse(res, 401, 'Incorrect email or password');
  }

  // Check if the password matches
  const passwordMatch = await bcrypt.compare(password, user.password);
  
  if (!passwordMatch) {
    return errorResponse(res, 401, 'Incorrect email or password');
  }

  // Check if the account is verified
  if (users) {
    if (users[user] === user.email && users[verified] ===! true) {
      return errorResponse(res, 403, 'Account not verified');
    }
  }

  // Generate an auth token (In production, use JWT)
  const authToken = 'mockAuthToken123'; // Replace with a JWT generation in production
  validAuthTokens.push(authToken);

  return successResponse(res, 'Login successful.', {
    auth_token: authToken,
  });
};

// Update Password
exports.updatePassword = async (req, res) => {
  const { password } = req.body;
  const authToken = req.headers['auth-token']; // Get auth token from the request header

  // Validate input
  if (!password) {
    return errorResponse(res, 400, 'Missing required field: password');
  }

  // Validate auth token (In production, verify the token with JWT or other secure methods)
  if (!authToken || authToken !== 'mockAuthToken123') {
    return errorResponse(res, 401, 'Invalid or expired auth-token');
  }

  // Validate password format (example: password length > 6)
  if (password.length < 6) {
    return errorResponse(res, 400, 'Invalid password format');
  }

  try {
    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update the password in the mock database
    const user = users.find(user => user.email === 'testuser@example.com'); // Replace with DB lookup
    if (!user) {
      return errorResponse(res, 404, 'User not found');
    }

    user.password = hashedPassword;

    return successResponse(res, 'Password updated successfully.');
  } catch (error) {
    return errorResponse(res, 500, 'Internal Server Error', error.message);
  }
};

exports.logout = (req, res) => {
    const authToken = req.headers['auth-token']; // Get auth token from the request header
    // console.log('Received auth-token:', authToken); // Log the received token
    // console.log('Valid tokens:', validAuthTokens); // Log valid tokens to check if it's matching
  
    // Validate auth token (In production, verify the token with JWT or other secure methods)
    if (!authToken || !validAuthTokens.includes(authToken)) {
      return errorResponse(res, 401, 'Invalid or expired auth-token');
    }
  
    // Remove the auth token (mock logout)
    validAuthTokens = validAuthTokens.filter(token => token !== authToken);
  
    return successResponse(res, 'Logout successful.');
  };
  
// Remove User Flow
// Updated Remove User implementation according to PDF
exports.removeUser = (req, res) => {
  const { email } = req.body;
  const authToken = req.headers['auth-token'];

  // Validate input
  if (!email) {
    return errorResponse(res, 400, 'Missing required field: email');
  }

  /*This is a hardcoded token for testing purposes, 
  assuming that the user with this token is an admin. 
  In a real-world scenario, the token would be a JWT 
  token containing user roles and permissions.*/

  // Validate auth token for admin access
  if (!authToken || authToken !== 'mockAdminToken') {
    return errorResponse(res, 403, 'Forbidden. Unauthorized access');
  }

  // Find and remove the user from the mock database
  const userIndex = users.findIndex(user => user.email === email);
  if (userIndex === -1) {
    return errorResponse(res, 404, 'Email not found');
  }

  // Remove user from the database
  users.splice(userIndex, 1);

  return successResponse(res, 'User account removed successfully.');
}; 

// Forgot Password Request
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;

  // Validate input
  if (!email) {
    return errorResponse(res, 400, 'Missing required field: email');
  }

  // Check if user exists
  const user = users.find(user => user.email === email);
  if (!user) {
    return errorResponse(res, 404, 'Email not found');
  }

  try {
    // Generate a random 6-digit code
    const resetCode = 123456;
    
    // Store the reset code with the email (In production, store with expiry)
    resetCodes[email] = resetCode;
    console.log('Code Saved! ', resetCodes);

    // In production, send this code via email using nodemailer
    console.log('Reset code for testing:', resetCode);

    return successResponse(res, 'Password reset code sent to email.', {
      code_sent: true
    });
  } catch (error) {
    return errorResponse(res, 500, 'Internal Server Error', error.message);
  }
};

// Validate Reset Code
exports.validateResetCode = (req, res) => {
  const { email, code } = req.body;

  // Validate input
  if (!email || !code) {
    return errorResponse(res, 400, 'Missing required fields');
  }

  // Check if user exists
  const user = users.find(user => user.email === email);
  if (!user) {
    return errorResponse(res, 404, 'Email not found');
  }

  // Validate the reset code
  const storedResetCode = resetCodes[email.toString()];

  // Check if reset code exists for this email
  if (!storedResetCode) {
    return errorResponse(res, 401, 'No reset code found. Please request a new code');
  }

  // Check if provided code matches stored code
  if (storedResetCode == code) {

    // Generate auth token for password reset
    const authToken = 'mockResetToken123'; // Replace with JWT in production
    validAuthTokens.push(authToken);

    // Clear the used reset code
    delete resetCodes[email];

    return successResponse(res, 'Code verified successfully.', {
      auth_token: authToken
    });
  } else {
      return errorResponse(res, 401, 'Error Code Mismatched!. Please request a new code');
  }
};