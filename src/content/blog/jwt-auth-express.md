---
author: Tanmay Panda
pubDatetime: 2025-02-09T16:00:00Z
modDatetime: 2025-02-09T16:00:00Z
title: Complete Guide to JWT Authentication and Authorization in Express
slug: jwt-authentication-authorization-express
featured: true
draft: false
tags:
  - jwt
  - authentication
  - authorization
  - express
  - security
  - nodejs
description: A comprehensive guide to implementing JWT-based authentication and authorization in Express applications, including best practices, security considerations, and complete implementation examples.
---

# Complete Guide to JWT Authentication and Authorization in Express

## Introduction

JSON Web Tokens (JWT) provide a stateless, secure way to handle authentication and authorization in modern web applications. This guide covers everything from basic concepts to advanced implementation patterns in Express.js applications.

## Understanding Authentication vs. Authorization

### Authentication

Authentication verifies the identity of a user or system. It answers the question "Who are you?" Think of it as checking an ID card at a secure building's entrance.

### Authorization

Authorization determines what an authenticated user can do. It answers the question "What are you allowed to do?" This is like checking if someone has the right security clearance to access specific areas once they're inside the building.

## JSON Web Tokens (JWT)

### What is JWT?

A JWT is a compact, URL-safe means of representing claims between two parties. It consists of three parts:

1. Header (Algorithm & token type)
2. Payload (Claims)
3. Signature

```typescript
// JWT structure
const header = {
  alg: "HS256",
  typ: "JWT",
};

const payload = {
  sub: "1234567890",
  name: "John Doe",
  role: "admin",
  iat: 1516239022,
};

const signature = HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
);
```

### Why Use JWT?

1. Stateless authentication
2. Cross-domain/CORS support
3. Performance (no database queries needed for verification)
4. Flexibility in storing user information
5. Support for mobile applications

## Implementation in Express

### Project Setup

```bash
npm init -y
npm install express jsonwebtoken bcryptjs cookie-parser dotenv mongoose
npm install --save-dev typescript @types/express @types/jsonwebtoken @types/bcryptjs @types/cookie-parser
```

### Directory Structure

```
src/
├── config/
│   └── database.ts
├── controllers/
│   ├── authController.ts
│   └── userController.ts
├── middleware/
│   ├── auth.ts
│   └── roleCheck.ts
├── models/
│   └── User.ts
├── routes/
│   ├── auth.ts
│   └── user.ts
├── types/
│   └── custom.d.ts
├── utils/
│   └── jwt.ts
└── app.ts
```

### Database Model

```typescript
// src/models/User.ts
import mongoose, { Document, Schema } from "mongoose";
import bcrypt from "bcryptjs";

export interface IUser extends Document {
  email: string;
  password: string;
  role: "user" | "admin";
  refreshToken?: string;
  comparePassword(candidatePassword: string): Promise<boolean>;
}

const userSchema = new Schema<IUser>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 8,
    },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
    refreshToken: String,
  },
  {
    timestamps: true,
  }
);

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error as Error);
  }
});

// Method to compare passwords
userSchema.methods.comparePassword = async function (
  candidatePassword: string
): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password);
};

export const User = mongoose.model<IUser>("User", userSchema);
```

### JWT Utilities

```typescript
// src/utils/jwt.ts
import jwt from "jsonwebtoken";
import { IUser } from "../models/User";

interface TokenPayload {
  userId: string;
  role: string;
}

export class JWTUtil {
  private static readonly ACCESS_TOKEN_SECRET = process.env.JWT_ACCESS_SECRET!;
  private static readonly REFRESH_TOKEN_SECRET =
    process.env.JWT_REFRESH_SECRET!;

  // Generate access token
  static generateAccessToken(user: IUser): string {
    const payload: TokenPayload = {
      userId: user._id,
      role: user.role,
    };

    return jwt.sign(payload, this.ACCESS_TOKEN_SECRET, {
      expiresIn: "15m", // Short-lived token
    });
  }

  // Generate refresh token
  static generateRefreshToken(user: IUser): string {
    const payload: TokenPayload = {
      userId: user._id,
      role: user.role,
    };

    return jwt.sign(payload, this.REFRESH_TOKEN_SECRET, {
      expiresIn: "7d", // Longer-lived token
    });
  }

  // Verify access token
  static verifyAccessToken(token: string): TokenPayload {
    return jwt.verify(token, this.ACCESS_TOKEN_SECRET) as TokenPayload;
  }

  // Verify refresh token
  static verifyRefreshToken(token: string): TokenPayload {
    return jwt.verify(token, this.REFRESH_TOKEN_SECRET) as TokenPayload;
  }
}
```

### Authentication Middleware

```typescript
// src/middleware/auth.ts
import { Request, Response, NextFunction } from "express";
import { JWTUtil } from "../utils/jwt";

declare global {
  namespace Express {
    interface Request {
      user?: {
        userId: string;
        role: string;
      };
    }
  }
}

export const authenticateToken = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(" ")[1];

    if (!token) {
      return res.status(401).json({ message: "Authentication required" });
    }

    const decoded = JWTUtil.verifyAccessToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
};
```

### Role-Based Authorization Middleware

```typescript
// src/middleware/roleCheck.ts
import { Request, Response, NextFunction } from "express";

export const requireRole = (roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ message: "Authentication required" });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        message: "Insufficient permissions",
      });
    }

    next();
  };
};
```

### Authentication Controller

```typescript
// src/controllers/authController.ts
import { Request, Response } from "express";
import { User } from "../models/User";
import { JWTUtil } from "../utils/jwt";

export class AuthController {
  // Register new user
  static async register(req: Request, res: Response) {
    try {
      const { email, password } = req.body;

      // Check if user exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: "Email already registered" });
      }

      // Create new user
      const user = new User({ email, password });
      await user.save();

      // Generate tokens
      const accessToken = JWTUtil.generateAccessToken(user);
      const refreshToken = JWTUtil.generateRefreshToken(user);

      // Save refresh token
      user.refreshToken = refreshToken;
      await user.save();

      // Set refresh token in HTTP-only cookie
      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      res.status(201).json({
        message: "User registered successfully",
        accessToken,
        user: {
          id: user._id,
          email: user.email,
          role: user.role,
        },
      });
    } catch (error) {
      res.status(500).json({ message: "Error registering user" });
    }
  }

  // Login user
  static async login(req: Request, res: Response) {
    try {
      const { email, password } = req.body;

      // Find user
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      // Verify password
      const isValidPassword = await user.comparePassword(password);
      if (!isValidPassword) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      // Generate tokens
      const accessToken = JWTUtil.generateAccessToken(user);
      const refreshToken = JWTUtil.generateRefreshToken(user);

      // Save refresh token
      user.refreshToken = refreshToken;
      await user.save();

      // Set refresh token in HTTP-only cookie
      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      res.json({
        accessToken,
        user: {
          id: user._id,
          email: user.email,
          role: user.role,
        },
      });
    } catch (error) {
      res.status(500).json({ message: "Error logging in" });
    }
  }

  // Refresh token
  static async refresh(req: Request, res: Response) {
    try {
      const refreshToken = req.cookies.refreshToken;

      if (!refreshToken) {
        return res.status(401).json({ message: "Refresh token required" });
      }

      // Verify refresh token
      const decoded = JWTUtil.verifyRefreshToken(refreshToken);

      // Find user
      const user = await User.findById(decoded.userId);
      if (!user || user.refreshToken !== refreshToken) {
        return res.status(403).json({ message: "Invalid refresh token" });
      }

      // Generate new tokens
      const accessToken = JWTUtil.generateAccessToken(user);
      const newRefreshToken = JWTUtil.generateRefreshToken(user);

      // Update refresh token
      user.refreshToken = newRefreshToken;
      await user.save();

      // Set new refresh token in cookie
      res.cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.json({ accessToken });
    } catch (error) {
      res.status(403).json({ message: "Invalid refresh token" });
    }
  }

  // Logout
  static async logout(req: Request, res: Response) {
    try {
      const refreshToken = req.cookies.refreshToken;

      if (refreshToken) {
        // Find user and remove refresh token
        await User.findOneAndUpdate(
          { refreshToken },
          { $unset: { refreshToken: 1 } }
        );
      }

      // Clear refresh token cookie
      res.clearCookie("refreshToken");
      res.json({ message: "Logged out successfully" });
    } catch (error) {
      res.status(500).json({ message: "Error logging out" });
    }
  }
}
```

### Routes Setup

```typescript
// src/routes/auth.ts
import { Router } from "express";
import { AuthController } from "../controllers/authController";

const router = Router();

router.post("/register", AuthController.register);
router.post("/login", AuthController.login);
router.post("/refresh", AuthController.refresh);
router.post("/logout", AuthController.logout);

export default router;

// src/routes/user.ts
import { Router } from "express";
import { UserController } from "../controllers/userController";
import { authenticateToken } from "../middleware/auth";
import { requireRole } from "../middleware/roleCheck";

const router = Router();

router.get("/profile", authenticateToken, UserController.getProfile);

router.get(
  "/admin/users",
  authenticateToken,
  requireRole(["admin"]),
  UserController.getAllUsers
);

export default router;
```

### Main Application Setup

```typescript
// src/app.ts
import express from "express";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import authRoutes from "./routes/auth";
import userRoutes from "./routes/user";

dotenv.config();

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);

// Error handling middleware
app.use(
  (
    err: Error,
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    console.error(err.stack);
    res.status(500).json({ message: "Something went wrong!" });
  }
);

// Database connection
mongoose
  .connect(process.env.MONGODB_URI!)
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.error("MongoDB connection error:", err));

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```

## Security Best Practices

### 1. Token Storage

- Store refresh tokens in HTTP-only cookies
- Never store access tokens in localStorage or cookies
- Keep access tokens in memory (React state/context)

### 2. Token Security

```typescript
// Secure cookie options
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  domain: process.env.COOKIE_DOMAIN,
};
```

### 3. CORS Configuration

````typescript
import cors from 'cors';

app.use(cors({
  origin: process.env.CLIENT_ORIGIN,
  credentials: true
  ```typescript
app.use(cors({
  origin: process.env.CLIENT_ORIGIN,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Authorization'],
  maxAge: 86400, // 24 hours in seconds
}));
````

### 4. Rate Limiting

```typescript
// src/middleware/rateLimiter.ts
import rateLimit from "express-rate-limit";

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: "Too many login attempts, please try again later",
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply to authentication routes
app.use("/api/auth/login", authLimiter);
app.use("/api/auth/register", authLimiter);
```

### 5. Request Validation

```typescript
// src/middleware/validation.ts
import { Request, Response, NextFunction } from "express";
import { z } from "zod";

const loginSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z.string().min(8, "Password must be at least 8 characters"),
});

export const validateLogin = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    loginSchema.parse(req.body);
    next();
  } catch (error) {
    if (error instanceof z.ZodError) {
      res.status(400).json({
        message: "Validation failed",
        errors: error.errors,
      });
    } else {
      next(error);
    }
  }
};
```

## Advanced Features

### 1. Token Blacklisting

```typescript
// src/models/TokenBlacklist.ts
import mongoose, { Document, Schema } from "mongoose";

interface ITokenBlacklist extends Document {
  token: string;
  expiresAt: Date;
}

const tokenBlacklistSchema = new Schema<ITokenBlacklist>({
  token: {
    type: String,
    required: true,
    unique: true,
  },
  expiresAt: {
    type: Date,
    required: true,
    expires: 0, // Document will be automatically deleted when expired
  },
});

export const TokenBlacklist = mongoose.model<ITokenBlacklist>(
  "TokenBlacklist",
  tokenBlacklistSchema
);

// src/middleware/checkBlacklist.ts
import { Request, Response, NextFunction } from "express";
import { TokenBlacklist } from "../models/TokenBlacklist";

export const checkBlacklist = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      return next();
    }

    const blacklisted = await TokenBlacklist.findOne({ token });

    if (blacklisted) {
      return res.status(401).json({ message: "Token has been revoked" });
    }

    next();
  } catch (error) {
    next(error);
  }
};
```

### 2. Multiple Device Management

```typescript
// src/models/Session.ts
import mongoose, { Document, Schema } from 'mongoose';

interface ISession extends Document {
  userId: mongoose.Types.ObjectId;
  deviceInfo: {
    userAgent: string;
    ip: string;
    lastActive: Date;
  };
  refreshToken: string;
}

const sessionSchema = new Schema<ISession>({
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  deviceInfo: {
    userAgent: String,
    ip: String,
    lastActive: {
      type: Date,
      default: Date.now,
    },
  },
  refreshToken: {
    type: String,
    required: true,
  },
}, {
  timestamps: true,
});

export const Session = mongoose.model<ISession>('Session', sessionSchema);

// Updated login controller
static async login(req: Request, res: Response) {
  try {
    // ... previous login logic ...

    // Create session
    const session = new Session({
      userId: user._id,
      deviceInfo: {
        userAgent: req.headers['user-agent'],
        ip: req.ip,
      },
      refreshToken,
    });
    await session.save();

    // ... rest of login logic ...
  } catch (error) {
    res.status(500).json({ message: 'Error logging in' });
  }
}
```

### 3. Password Reset Flow

```typescript
// src/controllers/passwordController.ts
import { Request, Response } from "express";
import { User } from "../models/User";
import { sendEmail } from "../utils/email";
import crypto from "crypto";

export class PasswordController {
  static async requestReset(req: Request, res: Response) {
    try {
      const { email } = req.body;
      const user = await User.findOne({ email });

      if (!user) {
        return res.status(200).json({
          message: "If an account exists, a reset link will be sent",
        });
      }

      const resetToken = crypto.randomBytes(32).toString("hex");
      const resetTokenHash = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");

      user.passwordResetToken = resetTokenHash;
      user.passwordResetExpires = new Date(Date.now() + 3600000); // 1 hour
      await user.save();

      const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;

      await sendEmail({
        to: user.email,
        subject: "Password Reset Request",
        text: `Click here to reset your password: ${resetUrl}`,
      });

      res.json({
        message: "If an account exists, a reset link will be sent",
      });
    } catch (error) {
      res.status(500).json({ message: "Error requesting password reset" });
    }
  }

  static async resetPassword(req: Request, res: Response) {
    try {
      const { token, password } = req.body;

      const resetTokenHash = crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

      const user = await User.findOne({
        passwordResetToken: resetTokenHash,
        passwordResetExpires: { $gt: Date.now() },
      });

      if (!user) {
        return res.status(400).json({ message: "Invalid or expired token" });
      }

      user.password = password;
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save();

      res.json({ message: "Password reset successful" });
    } catch (error) {
      res.status(500).json({ message: "Error resetting password" });
    }
  }
}
```

### 4. Activity Logging

```typescript
// src/middleware/activityLogger.ts
import { Request, Response, NextFunction } from "express";
import mongoose, { Document, Schema } from "mongoose";

interface IActivityLog extends Document {
  userId: mongoose.Types.ObjectId;
  action: string;
  ip: string;
  userAgent: string;
  details: Record<string, any>;
}

const activityLogSchema = new Schema<IActivityLog>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    action: {
      type: String,
      required: true,
    },
    ip: String,
    userAgent: String,
    details: Schema.Types.Mixed,
  },
  {
    timestamps: true,
  }
);

const ActivityLog = mongoose.model<IActivityLog>(
  "ActivityLog",
  activityLogSchema
);

export const logActivity = (action: string) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (req.user?.userId) {
        await ActivityLog.create({
          userId: req.user.userId,
          action,
          ip: req.ip,
          userAgent: req.headers["user-agent"],
          details: {
            method: req.method,
            path: req.path,
            query: req.query,
            body: req.body,
          },
        });
      }
      next();
    } catch (error) {
      next(error);
    }
  };
};
```

## Testing

### 1. Unit Tests

```typescript
// src/tests/auth.test.ts
import request from "supertest";
import { app } from "../app";
import { User } from "../models/User";
import { JWTUtil } from "../utils/jwt";

describe("Authentication", () => {
  beforeEach(async () => {
    await User.deleteMany({});
  });

  describe("POST /api/auth/register", () => {
    it("should register a new user", async () => {
      const res = await request(app).post("/api/auth/register").send({
        email: "test@example.com",
        password: "password123",
      });

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty("accessToken");
      expect(res.body.user).toHaveProperty("email", "test@example.com");
    });
  });

  describe("POST /api/auth/login", () => {
    beforeEach(async () => {
      await request(app).post("/api/auth/register").send({
        email: "test@example.com",
        password: "password123",
      });
    });

    it("should login successfully", async () => {
      const res = await request(app).post("/api/auth/login").send({
        email: "test@example.com",
        password: "password123",
      });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("accessToken");
    });
  });
});
```

## Deployment Considerations

### 1. Environment Variables

```bash
# .env.example
NODE_ENV=development
PORT=3000
MONGODB_URI=mongodb://localhost:27017/your-db
JWT_ACCESS_SECRET=your-access-secret
JWT_REFRESH_SECRET=your-refresh-secret
CLIENT_ORIGIN=http://localhost:3000
COOKIE_DOMAIN=localhost
```

### 2. Production Configuration

```typescript
// src/config/production.ts
export const productionConfig = {
  cors: {
    origin: process.env.CLIENT_ORIGIN,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  },
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    domain: process.env.COOKIE_DOMAIN,
  },
  mongodb: {
    url: process.env.MONGODB_URI,
    options: {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    },
  },
};
```

## Error Handling

```typescript
// src/utils/errors.ts
export class AppError extends Error {
  constructor(
    public statusCode: number,
    public message: string,
    public isOperational = true
  ) {
    super(message);
    Object.setPrototypeOf(this, AppError.prototype);
  }
}

// src/middleware/errorHandler.ts
import { Request, Response, NextFunction } from "express";
import { AppError } from "../utils/errors";

export const errorHandler = (
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (err instanceof AppError) {
    return res.status(err.statusCode).json({
      status: "error",
      message: err.message,
    });
  }

  console.error("Error:", err);

  res.status(500).json({
    status: "error",
    message: "Internal server error",
  });
};
```

## Conclusion

This guide covered the implementation of a secure, production-ready JWT authentication and authorization system in Express. Key takeaways:

1. Always use HTTPS in production
2. Implement proper token management
3. Use secure cookie settings
4. Implement rate limiting
5. Log security-related events
6. Handle errors gracefully
7. Follow security best practices

Remember to regularly:

- Update dependencies
- Rotate JWT secrets
- Monitor logs for suspicious activity
- Conduct security audits
- Keep up with security best practices

For more information, refer to:

- [OWASP Security Cheatsheet](https://cheatsheetseries.owasp.org/)
- [JWT Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
