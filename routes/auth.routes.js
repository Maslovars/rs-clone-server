const { Router } = require('express');
const router = Router();
const User = require('./models/User');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const { check, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const config = require('config');


router.post(
    '/register',
    [
        check('userName', 'Username must be at least 3 chars long').isLength({ min: 3 }),
        check('password')
            .isLength({ min: 6 })
            .withMessage('Password must be at least 6 chars long')
            .matches(/\d/)
            .withMessage('Password must contain a number')
            .matches(/\D/)
            .withMessage('Password must contain a char')
    ],
    async (req, res) => {
        try {

            // console.log('body:', req.body);

            const errors = validationResult(req);

            if (!errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: errors.array()[0].msg
                })
            }

            const { userName, password } = req.body;
            const candidate = await User.findOne({ userName });

            if (candidate) {
                return res.status(400).json({ message: 'Such username already exists!' });
            }

            const hashedPass = await bcrypt.hash(password, saltRounds);
            const user = new User({ userName, password: hashedPass });


            // console.log('hashedPass:', hashedPass);           

            await user.save();

            res.status(201).json({ message: 'User successfully created!' });
        } catch (err) {
            // console.log('err', err);
            res.status(500).json({ message: 'Something went wrong!' });
        }
    });

router.post(
    '/login',
    [
        check('userName', 'Enter correct username'),
        check('password', 'Enter correct password').exists()
    ],
    async (req, res) => {
        try {

            const errors = validationResult(req);

            if (!errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: "Invalid user's data"
                })
            }

            const { userName, password } = req.body;
            const user = await User.findOne({ userName });

            if (!user) {
                return res.status(400).json({ message: 'User does not exist' });
            }

            const isMatch = await bcrypt.compare(password, user.password);

            if (!isMatch) {
                return res.status(400).json({ message: 'Invalid password' });
            }

            const token = jwt.sign(
                { userId: user.id },
                config.get('jwtSecretKey'),
                { expiresIn: '24h' }
            );

            res.json({ token, userId: user.id });

        } catch (err) {
            console.log('err', err);
            res.status(500).json({ message: 'Something went wrong!' });
        }
    });

module.exports = router;