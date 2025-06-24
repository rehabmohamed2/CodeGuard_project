"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserService = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const uuid_1 = require("uuid");
class UserService {
    static users = []; // In production, use a database
    static getUserCount() {
        return this.users.length;
    }
    static async authenticate(username, password) {
        const user = this.users.find(u => u.username === username);
        if (!user)
            throw new Error('User not found');
        const isValid = await bcrypt_1.default.compare(password, user.passwordHash);
        if (!isValid)
            throw new Error('Invalid password');
        return user;
    }
    static async createUser(username, password, requesterId) {
        // If a requesterId is provided, ensure the requester exists and is an admin
        if (requesterId) {
            const requester = this.users.find(u => u.id === requesterId);
            if (!requester || requester.role !== 'admin') {
                throw new Error('Admin privileges required');
            }
        }
        // Check if the username already exists
        const exists = this.users.some(u => u.username === username);
        if (exists)
            throw new Error('User already exists');
        const salt = await bcrypt_1.default.genSalt(10);
        const passwordHash = await bcrypt_1.default.hash(password, salt);
        const newUser = {
            id: (0, uuid_1.v4)(),
            username,
            passwordHash,
            role: this.users.length === 0 ? 'admin' : 'user' // First user is admin
        };
        this.users.push(newUser);
        return newUser;
    }
    static async listUsers() {
        return this.users.map(u => ({ ...u, passwordHash: 'undefined' }));
    }
}
exports.UserService = UserService;
//# sourceMappingURL=user.js.map