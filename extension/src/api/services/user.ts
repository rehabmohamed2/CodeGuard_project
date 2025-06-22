import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';

interface User {
  id: string;
  username: string;
  passwordHash: string;
  role: 'admin' | 'user'; // Add role field
}

export class UserService {
  private static users: User[] = []; // In production, use a database

  static getUserCount(): number {
    return this.users.length;
  }

  static async authenticate(username: string, password: string): Promise<User> {
    const user = this.users.find(u => u.username === username);
    if (!user) throw new Error('User not found');
    
    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) throw new Error('Invalid password');
    
    return user;
  }

  static async createUser(username: string, password: string, requesterId?: string): Promise<User> {
    // If a requesterId is provided, ensure the requester exists and is an admin
    if (requesterId) {
      const requester = this.users.find(u => u.id === requesterId);
      if (!requester || requester.role !== 'admin') {
        throw new Error('Admin privileges required');
      }
    }
  
    // Check if the username already exists
    const exists = this.users.some(u => u.username === username);
    if (exists) throw new Error('User already exists');
  
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
  
    const newUser: User = {
      id: uuidv4(),
      username,
      passwordHash,
      role: this.users.length === 0 ? 'admin' : 'user' // First user is admin
    };
  
    this.users.push(newUser);
    return newUser;
  }  

  static async listUsers(): Promise<User[]> {
    return this.users.map(u => ({ ...u, passwordHash: 'undefined' }));
  }
}