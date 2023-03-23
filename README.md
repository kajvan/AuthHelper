README
This code provides a set of functions for password hashing and token authentication using bcrypt and jsonwebtoken libraries.

Dependencies
This code requires the following dependencies:

bcrypt
jsonwebtoken
timestringconverter
You can install these dependencies by running:

Functions
hashPassword(password: string): string
This function takes a plain-text password and returns a hashed password using bcrypt with the salt rounds set to 10.

comparePassword(password: string, hash: string): boolean
This function takes a plain-text password and a hashed password and returns a boolean indicating whether or not the plain-text password matches the hashed password.

generateToken(user: object, secret: string, expires: string): string
This function takes a user object, a secret key, and an optional expiration time and returns a JSON web token (JWT) using the jsonwebtoken library. The default expiration time is 24 hours, but you can specify a different expiration time in any format supported by the timestringconverter library.

verifyToken(token: string, secret: string): object | boolean
This function takes a JSON web token and a secret key and returns the decoded token payload if the token is valid and not expired, or false otherwise.

Example usage
javascript

const auth = require('./authhelp');

// Hash a password
const hashedPassword = auth.hashPassword('password123');

// Compare a plain-text password with a hashed password
const passwordMatches = auth.comparePassword('password123', hashedPassword);

// Generate a JSON web token
const user = { id: 123, name: 'John Doe' };
const secretKey = 'mysecretkey';
const token = auth.generateToken(user, secretKey, '30m'); // Expires in 30 minutes

// Verify a JSON web token
const decodedToken = auth.verifyToken(token, secretKey);
if (decodedToken) {
    console.log(decodedToken); // { id: 123, name: 'John Doe', exp: 1647994800 }
} else {
    console.log('Invalid or expired token');
}
License
This code is licensed under the ISC License.