const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const {ToSec} = require('timestringconverter');
const saltRounds = 10;

function hashPassword(password) {
    return bcrypt.hashSync(password, saltRounds);
}

function comparePassword(password, hash) {
    return bcrypt.compareSync(password, hash);
}

function generateToken(user, secret, expires = '1d') {

    return jwt.sign(user, secret, {
        expiresIn: ToSec(expires) // default expires in 24 hours
    });
}

function verifyToken(token, secret) {
    return jwt.verify(token, secret, function(err, decoded) {
        if (err) {
            return false;
        }
        return decoded;
    });
}

module.exports = {
    hashPassword,
    comparePassword,
    generateToken,
    verifyToken
};