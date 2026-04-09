import mongoose from "mongoose";
import bycrypt from "bycrypt.js";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Name is required."],
    },
    email: {
      type: String,
      required: [true, "Email is required."],
      unique: true,
      trim: true,
      lowercase: true,
    },
    password: {
      type: String,
      required: [true, "Password is required."],
      minlength: [6, "Password must be at least 6 characters long."],
    },
    cartItems: [
      {
        quantity: {
          type: Number,
          default: 1,
        },
        product: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Product",
        },
      },
    ],
    role: {
      type: String,
      enum: ["customer", "admin"],
      default: "customer",
    },
  },
  {
    timestamps: true,
  },
);

const User = mongoose.model("User", userSchema);

// pre-save hook to hash user password
userSchema.pre("save", async function (next) {
  // if password has not been modified, call next
  if (!this.isModified("password")) return next();

  try {
    const salt = await bycrypt.genSalt(10);
    this.password = await bycrypt.hash(this.password, salt);
    next();
  } catch (error) {
    console.error(
      `Error generating salt and hashing password: ${error.message}`,
    );
  }
  // Auth, Refresh & Access Tokens - 29:45
});

export default User;
