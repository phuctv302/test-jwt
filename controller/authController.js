const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const JWT = require('../utils/jwt');

const User = require('../models/userModel');

// create send TOKEN with COOKIE
const createSendToken = (user, statusCode, res) => {
    const token = JWT.signToken({ id: user._id });

    const cookieOptions = {
        expires: new Date(
            Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
        ),
        httpOnly: true,
    };

    if (process.env.NODE_ENV === 'production') {
        cookieOptions.secure = true;
    }
    // sending jwt via cookie
    res.cookie('jwt', token, cookieOptions);

    // Remove password from output
    user.password = undefined;

    res.status(statusCode).json({
		jwt:token,
        status: 'success',
        data: {
            user,
        },
    });
};

/**
 * PROTECT ROUTES: All routes after this route need to login to access
 */
exports.protect = catchAsync(async (req, res, next) => {
    // 1) Get token and check
    let token;
    if (
        req.headers.authorization &&
        req.headers.authorization.startsWith('Bearer')
    ) {
        token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.jwt) {
        token = req.cookies.jwt;
    }

    if (!token)
        return next(
            new AppError(
                'You are not logged in yet. Please login to access!',
                401
            )
        );

    // 2) Verification token
    const decoded = await JWT.decodeToken(token);

    // 3) Check if user still exists
    const currentUser = await User.findOne({ _id: decoded.id });
    if (!currentUser)
        return next(
            new AppError('The user belong to the token no longer exist!', 401)
        );


    // Put user on req
    req.user = currentUser;

    // Grant access for routes
    next();
});

/**
 * Give PERMISSION OF ACCESSING ROUTES depend USER'S ROLE
 */
exports.restrictTo = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return next(
                new AppError(
                    "You don't have permission to perform this action!",
                    403
                )
            );
        }
        next();
    };
};

/**
 * SIGN UP FUNCTION ~ CREATE NEW USER
 */
exports.signup = catchAsync(async (req, res, next) => {
    const newUser = await User.create(req.body);

    // Send token to client
    createSendToken(newUser, 201, res);
});

/**
 * LOGIN FUNCTION
 */
exports.login = catchAsync(async (req, res, next) => {
    const { email, password } = req.body;

    // 1) check if email and password exist
    if (!email || !password)
        return next(new AppError('Please provide email and password', 400));

    // 2) Check if user exists && password is correct
    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.correctPassword(password, user.password)))
        return next(new AppError('Incorrect email or password', 400));

    // 3) Send token to client
    createSendToken(user, 200, res);
});

/**
 * LOG OUT FUNCTION
 */
exports.logout = (req, res) => {
    res.cookie('jwt', 'logged_out', {
        expires: new Date(Date.now() + 500),
        httpOnly: true,
    });
    res.status(200).json({
        status: 'success',
    });
};
