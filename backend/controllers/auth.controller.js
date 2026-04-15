import { redis } from "../lib/redis.js";
import User from "../models/user.model.js";
import jwt from "jsonwebtoken";

// function to generate both access and refresh tokens (use env secrets)
const generateTokens = (userId) => {
  const accessToken = jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
  const refreshToken = jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });

  return { accessToken, refreshToken };
};

// function to store refresh token in Redis
const storeRefreshToken = async (userId, refreshToken) => {
  // set a 7d expiration on refresh token
  await redis.set(
    `refresh_token:${userId}`,
    refreshToken,
    "EX",
    7 * 24 * 60 * 60,
  );
};

// function to set browser cookies with access and refresh tokens
const setCookies = (res, accessToken, refreshToken) => {
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

// @TODO: 58:42

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
    res.status(500).json({ message: "Server error" });
  }
};

export const login = async (req, res) => {
  res.send("Login route called");
};

// function to delete Redis refresh token of userId
const deleteRefreshToken = async (userId) => {
  return await redis.del(`refresh_token:${userId}`);
};

// function to delete browser cookies (including access and refresh tokens)
const deleteCookies = (res) => {
  res.cookie("accessToken", { expires: "Thu, 01 Jan 1970 00:00:00 UTC" });
  res.cookie("refreshToken", { expires: "Thu, 01 Jan 1970 00:00:00 UTC" });
};

export const logout = async (req, res) => {
  try {
    // deconstruct request body
    const { email } = req.body;
    const user = await User.findOne({ email });
    // if user does not exist, exit early
    if (!user) {
      return res.status(200).json({ message: "User does not exist" });
    }
    const delResponse = await deleteRefreshToken(user._id);
    if (!delResponse) {
      return res.status(200).json({ message: "User already logged out" });
    }
    deleteCookies(res);
    res.status(200).json({ message: "User successfully logged out" });
  } catch (error) {
    console.error(`Error: ${error.message}`);
    res.status(500).json({ message: "Server error" });
  }
};
