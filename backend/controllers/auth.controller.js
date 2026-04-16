import { redis } from "../lib/redis.js";
import User from "../models/user.model.js";
import jwt from "jsonwebtoken";

// function to generate both access and refresh tokens (use env secrets)
export const generateTokens = (userId) => {
  const accessToken = jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
  const refreshToken = jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });

  return { accessToken, refreshToken };
};

// function to store refresh token in Redis
export const storeRefreshToken = async (userId, refreshToken) => {
  // set a 7d expiration on refresh token
  await redis.set(
    `refresh_token:${userId}`,
    refreshToken,
    "EX",
    7 * 24 * 60 * 60,
  );
};

// function to set browser cookies with access and refresh tokens
export const setCookies = (res, accessToken, refreshToken) => {
  res.cookie("accessToken", accessToken, {
    httpOnly: true, // prevents cross site scripting (XSS) attacks
    secure: process.env.NODE_ENV === "production", // make this https if environment is production
    sameSite: "strict", // prevents cross site request forgery (CSRR) attacks
    maxAge: 15 * 60 * 1000, // 15 minute TTL
  });
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true, // prevents cross site scripting (XSS) attacks
    secure: process.env.NODE_ENV === "production", // make this https if environment is production
    sameSite: "strict", // prevents cross site request forgery (CSRR) attacks
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 day TTL
  });
};

export const signup = async (req, res) => {
  try {
    // deconstruct request body
    const { email, password, name } = req.body;

    // if user already exists, send 400
    const userExists = await User.findOne({ email });
    if (userExists) {
      console.warn(`Warning: User already exists`);
      return res.status(400).json({ message: "User already exists" });
    }

    // create user
    const user = await User.create({
      name: name,
      email: email,
      password: password,
    });

    // authenticate user
    const { accessToken, refreshToken } = generateTokens(user._id);
    await storeRefreshToken(user._id, refreshToken);
    setCookies(res, accessToken, refreshToken);

    res.status(201).json({ user: user, message: "User created successfully" });
  } catch (error) {
    console.error(`Error: ${error.message}`);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    // if user exists and password matches, generate tokens
    if (user && (await user.comparePassword(password))) {
      // authenticate user
      const { accessToken, refreshToken } = generateTokens(user._id);
      await storeRefreshToken(user._id, refreshToken);
      setCookies(res, accessToken, refreshToken);
      return res.status(200).json({ message: "User logged in successfully"});
    } else {
      // else, cannot authenticate
      console.warn("Email and/or password incorrect");
      res.status(400).json({ message: "Email and/or password incorrect" });
    }
  } catch (error) {
    console.error(`Server error: ${ error.message }`);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

export const logout = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
      try {
        const decoded = jwt.verify(
          refreshToken,
          process.env.REFRESH_TOKEN_SECRET,
        );
        await redis.del(`refresh_token:${decoded.userId}`);
      } catch (tokenError) {
        // Token invalid/expired, but still clear cookies
        console.warn(`Invalid refresh token during logout: ${tokenError.message}`);
      }
    }
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    return res.status(200).json({ message: "User logged out successfully" });
  } catch (error) {
    console.error(`Error: ${error.message}`);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};
