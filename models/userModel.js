const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        unique: [true, 'Username must be unique'],
        trim: true,
        lowercase: true,
        required: [true, 'Username is required'],
    },
    email: {
        type: String,
        unique: [true, 'Email must be unique'],
        validate: [validator.isEmail, 'Please input a valid email'],
        required: [true, 'Email is required'],
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user',
    },
    password: {
        type: String,
        required: true,
        select: false,
    },
    passwordConfirm: {
        type: String,
        validate: {
            validator: function (val) {
                return this.password === val;
            },
            message: 'Password confirm must be the same',
        },
    },
});

// ENCRYPT PASSWORD BEFORE SAVING TO DB
userSchema.pre('save', async function (next) {
    // Only run if password is modified
    if (!this.isModified('password')) return next();

    // Hash the password with cost of 12
    this.password = await bcrypt.hash(this.password, 12);

    // Delete passwordConfirm
    this.passwordConfirm = undefined;

    next();
});

// INSTANCE METHOD: Check password to login
userSchema.methods.correctPassword = async function (
    candidatePassword,
    userPassword
) {
    return await bcrypt.compare(candidatePassword, userPassword);
};

const User = mongoose.model('User', userSchema);
module.exports = User;
