const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require("../models/user");
const validator = require("validator");
const Post = require("../models/post");
const {JWT_SECRET} = require('../../secrets');
const { clearImage } = require('../util/file');


const checkAuth = (req) => {
  if (!req.isAuth) {
    const error = new Error('Not authenticated');
    error.code = 401;
    throw error;
  }
}

const checkPost = (post) => {
  if (!post) {
    const error = new Error('Post not found');
    error.code = 404;
    throw error;
  }
}

const checkPostOwner = (post, req) => {
  if (post.creator._id.toString() !== req.userId.toString()) {
    const error = new Error('Not authorized');
    error.code = 403;
    throw error;
  }
}

module.exports = {
  createUser: async function ({ userInput }, req) {

    const errors = [];

    if (!validator.isEmail(userInput.email)) {
      errors.push("Email is invalid");
    }

    if (validator.isEmpty(userInput.password) || !validator.isLength(userInput.password, {min: 5})) {
      errors.push("Password too short");
    }

    if (errors.length > 0) {
      const error = new Error('invalid input.');
      error.data = errors;
      error.code = 422;
      throw error;
    }

    const existingUser = await User.findOne({ email: userInput.email });

    if (existingUser) {
      const error = new Error("User already exists");
      throw error;
    }

    const hashedPw = await bcrypt.hash(userInput.password, 12);
    const user = new User({
      email: userInput.email,
      name: userInput.name,
      password: hashedPw,
    });
    const createdUser = await user.save();
    return {
      ...createdUser._doc,
      _id: createdUser._id.toString(),
    }
  },
  login: async function ({ email, password }) {
    const user = await User.findOne({ email: email });

    if (!user) {
      const error = new Error('User not found');
      error.code = 401;
      throw error;
    }

    const isEqual = await bcrypt.compare(password, user.password);

    if (!isEqual) {
      const error = new Error('Password is incorrect');
      error.code = 401;
      throw error;
    }

    const token = jwt.sign({
      userId: user._id.toString(),
      email: user.email
    }, JWT_SECRET, { expiresIn: '1h' });

    return {
      token: token,
      userId: user._id.toString()
    }
  },
  createPost: async function ({ postInput }, req) {
    checkAuth(req);

    const errors = [];

    if (validator.isEmpty(postInput.title) || !validator.isLength(postInput.title, {min: 5})) {
      errors.push({message: "Title is required"});
    }
    if (validator.isEmpty(postInput.content) || !validator.isLength(postInput.content, {min: 5})) {
      errors.push({message: "Content is required"});
    }
    
    if (errors.length > 0) {
      const error = new Error('Invalid input');
      error.data = errors;
      error.code = 422;
      throw error;
    }
    const user = await User.findById(req.userId);

    if (!user) {
      const error = new Error('User not found');
      error.code = 401;
      throw error;
    }

    const post = new Post({
      title: postInput.title,
      content: postInput.content,
      imageUrl: postInput.imageUrl,
      creator: user,
    });
    const createdPost = await post.save();

    user.posts.push(createdPost);
    await user.save();
    
    return {
      ...createdPost._doc,
      _id: createdPost._id.toString(),
      createdAt: createdPost.createdAt.toISOString(),
      updatedAt: createdPost.updatedAt.toISOString(),
    }
  },
  posts: async function ({page}, req) {
    checkAuth(req);

    if (!page) {
      page = 1;
    }

    const perPage = 2;
    const totalPosts = await Post.find().countDocuments();
    const posts = await Post.find()
    .sort({createdAt: -1})
    .skip((page - 1) * perPage)
    .limit(perPage)
    .populate('creator');

    return {
      posts: posts.map(post => ({
        ...post._doc,
        _id: post._id.toString(),
        createdAt: post.createdAt.toISOString(),
        updatedAt: post.updatedAt.toISOString(),
      })),
      totalPosts: totalPosts
    }
  },
  post: async function ({id}, req) {
    checkAuth(req);

    const post = await Post.findById(id).populate('creator');

    checkPost(post);

    return {
      ...post._doc,
      _id: post._id.toString(),
      createdAt: post.createdAt.toISOString(),
      updatedAt: post.updatedAt.toISOString(),
    };
  },
  updatePost: async function ({id, postInput}, req) {
    checkAuth(req);

    const post = await Post.findById(id).populate('creator');

    checkPost(post);

    checkPostOwner(post, req);

    // TODO DRY
    const errors = [];

    if (validator.isEmpty(postInput.title) || !validator.isLength(postInput.title, {min: 5})) {
      errors.push({message: "Title is required"});
    }
    if (validator.isEmpty(postInput.content) || !validator.isLength(postInput.content, {min: 5})) {
      errors.push({message: "Content is required"});
    }
    
    if (errors.length > 0) {
      const error = new Error('Invalid input');
      error.data = errors;
      error.code = 422;
      throw error;
    }

    post.title = postInput.title;
    post.content = postInput.content;
    
    if (postInput.imageUrl !== 'undefined') {
      post.imageUrl = postInput.imageUrl;
    }

    const updatedPost = await post.save();

    return {
      ...updatedPost._doc,
      _id: updatedPost._id.toString(),
      createdAt: updatedPost.createdAt.toISOString(),
      updatedAt: updatedPost.updatedAt.toISOString(),
    }
  },
  deletePost: async function ({id}, req) {
    checkAuth(req);

    const post = await Post.findById(id);

    checkPost(post);

    if (post.creator.toString() !== req.userId.toString()) {
      const error = new Error('Not authorized');
      error.code = 403;
      throw error;
    }

    clearImage(post.imageUrl);

    await Post.findByIdAndRemove(id);

    const user = await User.findById(req.userId);

    user.posts.pull(id);
    await user.save();

    return true;
  },
  user: async function (args, req) {
    checkAuth(req);

    const user = await User.findById(req.userId);

    if (!user) {
      const error = new Error('User not found');
      error.code = 404;
      throw error;
    }

    return {
      ...user._doc,
      _id: user._id.toString(),
    }
  },
  updateStatus: async function ({status}, req) {
    checkAuth(req);

    const user = await User.findById(req.userId);

    if (!user) {
      const error = new Error('User not found');
      error.code = 404;
      throw error;
    }

    user.status = status;
    await user.save();

    return {
      ...user._doc,
      _id: user._id.toString(),
    }
  }

}