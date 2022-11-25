import _ from "lodash";
import upload from "../utils/multer.js";
import bcrypt from "bcrypt";
import express from "express";
import {
  UserModel,
  validateUserLogin,
  validateUsers,
  validateUserPin,
} from "../Models/Users.model.js";
const router = express.Router();

router.post("/login", async (req, res) => {
  const { error } = validateUserLogin(req.body);
  if (error) return res.status(400).send(error.details[0].message);
  try {
    const userInfo = await UserModel.findOne({ username: req.body.username });
    if (!userInfo) return res.status(406).send({ message: "Invalid username" });
    const validatePassword = bcrypt.compareSync(
      req.body.password,
      userInfo.password
    );
    if (!validatePassword) return res.send({ message: "Invalid password" });
    // Generate Token and pass though header
    const token = await userInfo.generateAuthToken();
    res.header("authorization", token).json({
      success: 200,
      userInfo: userInfo._id,
      accessToken: token,
    });
  } catch (error) {
    res.send({
      status: 404,
      message: `Error: ${error}`,
    });
  }
});

router.post("/loginWithPin", async (req, res) => {
  const { error } = validateUserPin(req.body);
  if (error) return res.status(400).send(error.details[0].message);
  try {
    const userInfo = await UserModel.findOne({ pin_Number: req.body.pin_Number });
    if (!userInfo) return res.status(406).send({ message: "Invalid Pin" });
    // Generate Token and pass though header
    const token = await userInfo.generateAuthToken();
    res.header("authorization", token).json({
      success: 200,
      userInfo: userInfo._id,
      accessToken: token,
    });
  } catch (error) {
    res.send({
      status: 404,
      message: `Error: ${error}`,
    });
  }
});

router.post("/create-user", upload.single("avatar"), async function (req, res) {
  const { error } = validateUsers(req.body);
  if (error) return res.status(406).send({ message: error.details[0].message });
  const checkUsername = await UserModel.findOne({
    username: req.body.username,
  });
  if (checkUsername)
    return res.send({
      message: `username: ${checkUsername.username} is already exists...`,
    });

  const chechPin = await UserModel.findOne({ pin_Number: req.body.pin_Number });
  if (chechPin)
    return res.send({
      message: `Please make sure to put a different pin number`,
    });

  // get avatar in file
  const avatar = req.file ? req.file.path : "uploads\\default.png";

  try {
    let AccountNo = 0;
    let [respnse] = await UserModel.find({}).sort({ createdAt: -1 }).limit(1);
    if (respnse) {
      AccountNo = respnse.accountNo + 1;
    } else {
      AccountNo = 3000;
    }

    const userinfo = new UserModel({
      avatar: avatar,
      name: req.body.name,
      email: req.body.email,
      phone: req.body.phone,
      username: req.body.username,
      password: req.body.password,
      pin_Number: req.body.pin_Number,
      accountNo: AccountNo,
    });
    const salt = await bcrypt.genSalt(10);
    userinfo.password = await bcrypt.hash(userinfo.password, salt);
    const result = await userinfo.save();

    let sendData = { ...result._doc };
    delete sendData.password;
    delete sendData.__v;

    res.send({
      status: 200,
      message: "User Registered Successfully",
      userInfo: sendData,
    });
  } catch (er) {
    res.send({
      status: 400,
      message: `Error: ${er}`,
    });
  }
});

export default router;
