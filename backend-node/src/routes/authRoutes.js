const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

router.post('/login', authController.login);
router.post('/logout', authController.logout);
router.get('/status', authController.checkAuthStatus);
router.get('/session', authController.getSession);
router.post('/create-account', authController.createAccount);
router.get('/fetch-user-data', authController.fetchUserData);

module.exports = router;
