
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"
import mongoose from "mongoose";

// COOKIE OPTIONS
// Login এবং Logout-এ একই options ব্যবহার করতে হবে।
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite:
    process.env.NODE_ENV === "production" ? "none" : "lax",
  path: "/",
};

// GENERATE ACCESS AND REFRESH TOKENS
const generateAccessAndRefereshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);

    if (!user) {
      throw new ApiError(404, "User not found");
    }

    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;

    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }

    throw new ApiError(
      500,
      "Something went wrong while generating access and refresh tokens"
    );
  }
};

// REGISTER USER
const registerUser = asyncHandler(async (req, res) => {
  const { fullName, email, username, password } = req.body || {};

  if (
    [fullName, email, username, password].some(
      (field) =>
        typeof field !== "string" || field.trim() === ""
    )
  ) {
    throw new ApiError(400, "All fields are required");
  }

  const normalizedUsername = username.trim().toLowerCase();
  const normalizedEmail = email.trim().toLowerCase();

  // CHECK EXISTING USER
  const existedUser = await User.findOne({
    $or: [
      { username: normalizedUsername },
      { email: normalizedEmail },
    ],
  });

  if (existedUser) {
    throw new ApiError(
      409,
      "User with email or username already exists"
    );
  }

  // GET IMAGE PATHS
  const avatarLocalPath = req.files?.avatar?.[0]?.path;
  const coverImageLocalPath = req.files?.coverImage?.[0]?.path;

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required");
  }

  // UPLOAD AVATAR
  const avatar = await uploadOnCloudinary(avatarLocalPath);

  if (!avatar?.url) {
    throw new ApiError(400, "Avatar upload failed");
  }

  // UPLOAD COVER IMAGE ONLY IF PROVIDED
  let coverImageUrl = "";

  if (coverImageLocalPath) {
    const coverImage = await uploadOnCloudinary(
      coverImageLocalPath
    );

    coverImageUrl = coverImage?.url || "";
  }

  // CREATE USER
  const user = await User.create({
    fullName: fullName.trim(),
    email: normalizedEmail,
    username: normalizedUsername,
    password,
    avatar: avatar.url,
    coverImage: coverImageUrl,
  });

  // REMOVE SENSITIVE FIELDS
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  if (!createdUser) {
    throw new ApiError(
      500,
      "Something went wrong while registering the user"
    );
  }

  return res.status(201).json(
    new ApiResponse(
      201,
      createdUser,
      "User registered successfully"
    )
  );
});

// LOGIN USER
const loginUser = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body || {};

  if (
    (typeof username !== "string" || !username.trim()) &&
    (typeof email !== "string" || !email.trim())
  ) {
    throw new ApiError(400, "Username or email is required");
  }

  if (typeof password !== "string" || !password) {
    throw new ApiError(400, "Password is required");
  }

  // FIND USER
  const conditions = [];

  if (username?.trim()) {
    conditions.push({
      username: username.trim().toLowerCase(),
    });
  }

  if (email?.trim()) {
    conditions.push({
      email: email.trim().toLowerCase(),
    });
  }

  const user = await User.findOne({
    $or: conditions,
  });

  if (!user) {
    throw new ApiError(404, "User does not exist");
  }

  // CHECK PASSWORD
  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid user credentials");
  }

  // GENERATE TOKENS
  const { accessToken, refreshToken } =
    await generateAccessAndRefereshTokens(user._id);

  // GET SAFE USER DATA
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  return res
    .status(200)
    .cookie("accessToken", accessToken, cookieOptions)
    .cookie("refreshToken", refreshToken, cookieOptions)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User logged in successfully"
      )
    );
});

// LOGOUT USER
const logoutUser = asyncHandler(async (req, res) => {
  if (!req.user?._id) {
    throw new ApiError(401, "Unauthorized request");
  }

  // REMOVE REFRESH TOKEN FROM DATABASE
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $unset: {
        refreshToken: 1,
      },
    }
  );

  // CLEAR COOKIES USING THE SAME OPTIONS AS LOGIN
  return res
    .status(200)
    .clearCookie("accessToken", cookieOptions)
    .clearCookie("refreshToken", cookieOptions)
    .json(
      new ApiResponse(
        200,
        {},
        "User logged out successfully"
      )
    );
});

const refreshAccessToken=asyncHandler(async(req , res)=>{
  const incomingRefreshToken=req.cookies.refreshToken || req.body.refreshToken

  if(!incomingRefreshToken){
    throw new ApiError(401,"unauthorized request")
  }
 try {
   const decodeToken=jwt.verify(incomingRefreshToken,process.env.REFRESH_TOKEN_SECRET)
   const user=await User.findById(decodeToken?._id)
 
   if(!user){
     throw new ApiError(401,"Invalid refresh token")
   }
   if(incomingRefreshToken !==user?.refreshToken){
     throw new ApiError(401,"Refresh token is expired or used")
   }
    const {accessToken,refreshToken:newrefreshToken}=await generateAccessAndRefereshTokens(user._id)
    return res.status(200).cookie("accessToken",accessToken,cookieOptions).cookie("refreshToken",newrefreshToken,cookieOptions)
    .json(
     new ApiResponse(
       200,
       {accessToken,refreshToken:newrefreshToken},
       "Access token refreshed"
     )
    )
 } catch (error) {
   throw new ApiError(401,error?.message||"Invalid refresh token")
 }
});

const changeCurrentPassword=asyncHandler(async(req,res)=>{ 
  const {oldPassword,newPassword}=req.body

  const user=await User.findById(req.user?._id)
  const isPasswordCorrect=await user.isPasswordCorrect(oldPassword)

  if(!isPasswordCorrect){
    throw new ApiError(400,"Invalid old password")
  }
  user.password=newPassword
  await user.save({validateBeforeSave:false})
  return res.status(200).json(new ApiResponse(200,{},"Password changed successfully"))
});

const getCurrentUser=asyncHandler(async(req,res)=>{
  return res
  .status(200)
  .json(new ApiResponse(200,req.user,"current user fetcged succesfully"))
});

const updateAccountDetails=asyncHandler(async(req,res)=>{
  const {fullName,email}=req.body

  if(!fullName ||!email){
    throw new ApiError(400,"All fields are required")
  }
  const user= await User.findByIdAndUpdate(req.user?._id,
    {
      $set:{
        fullName:fullName,
        email:email
      }
    },
    {
      new:true
    }
  ).select("-password")
  return res
  .status(200)
  .json(new ApiResponse(200,user,"Account details updated successfully"))
});
 
const updateUserAvatar=asyncHandler(async(req,res)=>{
  const avatarLocalPath=req.file?.path
  if(!avatarLocalPath){
    throw new ApiError(400,"Avatar file is missing")
  }
  const avatar=await uploadOnCloudinary(avatarLocalPath)

  if(!avatar.url){
    throw new ApiError(400,"Error while uploading on avatar")
  }
   const user=await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set:{
        avatar:avatar.url
      }
    },
    {
      new:true
    }
  ).select("-password")
  return res.status(200)
  .json(
    new ApiResponse(200,user,"Avatar image updated successfully")
  )
});

const updateUserCoverImage=asyncHandler(async(req,res)=>{
  const coverImageLocalPath=req.file?.path
  if(!coverImageLocalPath){
    throw new ApiError(400,"coverImage file is missing")
  }
  const coverImage=await uploadOnCloudinary(coverImageLocalPath)
  if(!coverImage.url){
    throw new ApiError(400,"error while upload on coverimage")
  }
  const user=await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set:{
        coverImage:coverImage.url
      }
    },
    {
      new:true
    }
  ).select("-password")
  return res.status(200)
  .json(
    new ApiResponse(200,user,"Cover image updated successfully")
  )
});

const getUserChannelProfile=asyncHandler(async(req,res)=>{
  const {username}=req.params
  if(!username?.trim()){
    throw new ApiError(400,"usename is missing")
  }

  const channel=await User.aggregate([
    {
      $match:{
        username:username?.toLowerCase()
      }
    },
    {
      $lookup:{
        from:"subscriptions",
        localField:"_id",
        foreignField:"channel",
        as:"subscribers"
      }
    },
    {
      $lookup:{
        from:"subscriptions",
        localField:"_id",
        foreignField:"subscriber",
        as:"subscribedTo"
      }
    },
    {
      $addFields:{
        subscribersCount:{
          $size:"$subscribers"
        },
        channelsSubscribedToCount:{
          $size:"$subscribedTo"
        },
        isSubscribed:{
          $cond:{
            if:{$in:[req.user?._id,"$subscribers.subscriber"]},
            then:true,
            else:false
          }
        }
      }
    },
    {
      $project:{
        fullName:1,
        username:1,
        subscribersCount:1,
        channelsSubscribedToCount:1,
        isSubscribed:1,
        avatar:1,
        coverImage:1,
        email:1
      }
    }
  ])
  if(!channel?.length){
    throw new ApiError(404,"channel does not exists")
  }
  return res
  .status(200)
  .json(
    new ApiResponse(200,channel[0],"User channel fetched successfully")
  )
})

const getWatchHistory=asyncHandler(async(req,res)=>{
    const user=await User.aggregate([
      {
        $match:{
          _id:new mongoose.Types.ObjectId(req.user._id)
        }
      },
      {
        $lookup:{
          from:"videos",
          localField:"watchHistory",
          foreignField:"_id",
          as:"watchHistory",
          pipeline:[
            {
              $lookup:{
                from:"users",
                localField:"owner",
                foreignField:"_id",
                as:"owner",
                pipeline:[
                  {
                    $project:{
                      fullName:1,
                      username:1,
                      avatar:1
                    }
                  }
                ]
              }
            },
            {
              $addFields:{
                owner:{
                  $first:"$owner"
                }
              }
            }
          ]
        }
      }
    ])
    return res.status(200)
    .json(
      new ApiResponse(
        200,
        user[0].watchHistory,"watch history fetched successfully"
      )
    )
})
export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateAccountDetails,
  updateUserAvatar,
  updateUserCoverImage,
  getUserChannelProfile,
  getWatchHistory
};
