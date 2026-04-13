import Redis from "ioredis";
import dotenv from "dotenv";

// load env configuration
dotenv.config();

// create Redis client using token-embedded URL
export const redis = new Redis(process.env.REDIS_URL);
