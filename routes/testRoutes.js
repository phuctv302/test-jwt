const express = require('express');

const authController = require('../controller/authController');
const testController = require('../controller/testController');

const router = express.Router();


router.get('/public', testController.test('Public content'))

router.use(authController.protect)
router.get('/login', testController.test('Needed login content'))
router.get('/user', authController.restrictTo('user'), testController.test('User content'))
router.get('/admin', authController.restrictTo('admin'), testController.test('Admin content'))

module.exports = router;