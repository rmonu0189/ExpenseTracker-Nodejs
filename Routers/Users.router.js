import fs from "fs";
import _ from "lodash";
import bcrypt from "bcrypt";
import express from "express";
import auth from "../Middlewares/Auth.middleware.js";

import {
  UserModel,
  updateValidation,
} from "../Models/Users.model.js";

const router = express.Router();
router.use(auth);

router.get("/me", async function (req, res) {
  const user = await UserModel.findById(req.user._id).select("-pin");
  // .select('-password '); this means ka reeb password ka xogta aad so celneysid
  // .select('-password -email'); email and password ka reeb xogta
  user.password = undefined;
  res.send({
    status: 200,
    message: "Successfull",
    user: user
  });
});

router.get("/", async function (req, res) {
  try {
    const usersInfo = await UserModel.find().select("-pin");
    res.send({
      status: 200,
      message: "Successfull",
      Users: usersInfo,
    });
  } catch (e) {
    res.send({
      status: 404,
      message: `Error: ${e}`,
    });
  }
});

router.get("/:id", async function (req, res) {
  try {
    const userinfo = await UserModel.findById(req.params.id);
    if (!userinfo)
      return res.status(404).send({
        status: 404,
        message: "User not found",
      });
      userinfo.password = undefined;
    res.send({
      status: 200,
      message: "Successfull",
      user: userinfo
    });
  } catch (e) {
    res.send({
      status: 404,
      message: `Error: ${e}`,
    });
  }
});

router.delete("/:id", async function (req, res) {
  try {
    const userInfo = await UserModel.findByIdAndRemove(req.params.id);
    if (!userInfo) return res.status(404).send("ID was not found");
    res.send({
      status: 200,
      message: "Seccessfully Deleted",
    });
  } catch (e) {
    res.send({
      status: false,
      message: `Error: ${e}`,
    });
  }
});

// updating user's password only (forgetpassword)
// "/:userID/:Transtype"
router.put("/passUpdate", async function (req, res) {
  const { phone, pin } = req.body;
  const userInfo = await UserModel.findOne({
    phone: phone,
  });
  if (!userInfo)
    return res.send({
      status: 404,
      message: "your phone is incorrect, please try again !",
    });
  // res.send(userInfo)

  const { _id } = userInfo;
  const salt = await bcrypt.genSalt(10);
  const pcript_pin = await bcrypt.hash(pin, salt);
  // res.send(pcript_pin)

  const _ = await UserModel.findByIdAndUpdate(
    _id,
    {
      pin: pcript_pin,
    },
    { new: true }
  );
  res.send({
    status: 200,
    message: "Your Password Updated SuccessFully",
  });
});

// updating user info without password
router.put("/update-userinfo/:id", async (req, res) => {
  const { error } = updateValidation(req.body);
  if (error)
    return res.status(404).send({ message: `${error.details[0].message}` });
  try {
    const id = await UserModel.findById(req.params.id);
    if (!id) return res.status(404).send({ message: "Not Found" });

    const checkUsername = await UserModel.findOne({
      username: req.body.username,
    }).lean();

    if (checkUsername) {
      res.send({
        message: `username: ${checkUsername.username} is already exists...`,
      });
    } else {
      // get avatar in file. check the file has path.
      const avatar = req.file ? req.file.path : "uploads\\default.png";

      // delete old image. if is not equal default.
      if (id.avatar !== "uploads\\default.png") {
        fs.unlink(id.avatar, function (err) {
          if (err) return console.log(err);
          // if no error, file has been deleted successfully
          console.log("File deleted!");
        });
      }

      const _ = await UserModel.findByIdAndUpdate(
        req.params.id,
        {
          avatar: avatar,
          name: req.body.name,
          email: req.body.email,
          phone: req.body.phone,
          username: req.body.username,
        },
        { new: true }
      );
      res.send({
        status: 200,
        message: "Updated Successfully",
      });
    }
  } catch (e) {
    res.send({ status: 404, message: `Error: ${e}` });
  }
});

// Change password with check old password
router.put("/change-password/:id", async (req, res) => {
  const { error } = changePasswordValidation(req.body);
  if (error)
    return res.status(404).send({ message: `${error.details[0].message}` });
  try {
    const id = await UserModel.findById(req.params.id);
    if (!id) return res.status(404).send({ message: "Not Found" });
  } catch (e) {
    res.send({ status: 404, message: `Error: ${e}` });
  }
  try {
    const salt = await bcrypt.genSalt(10);
    const pcript_pin = await bcrypt.hash(req.body.pin_Number, salt);
    const _ = await UserModel.findByIdAndUpdate(
      req.params.id,
      {
        password: pcript_pin,
      },
      { new: true }
    );
    res.send({
      status: 200,
      message: "Password Updated Successfully",
    });
  } catch (e) {
    res.send({ status: 404, message: `Error: ${e}` });
  }
});

// router.put("/update-user/:id", upload.single("avatar"), async (req, res) => {
//   const { error } = validateUsers(req.body);
//   if (error) return res.status(400).send(error.details[0].message);
//   try {
//     // console.log(req.body);
//     const id = await UserModel.findById(req.params.id);
//     if (!id) return res.status(400).send({ message: "ID was not found" });

//     // get avatar in file. check the file has path.
//     const avatar = req.file ? req.file.path : "uploads\\default.png";

//     // delete old image. if is not equal default.
//     if (id.avatar !== "uploads\\default.png") {
//       fs.unlink(id.avatar, function (err) {
//         if (err) return console.log(err);
//         // if no error, file has been deleted successfully
//         // console.log("File deleted!");
//       });
//     }

//     const salt = await bcrypt.genSalt(10);
//     const hashPass = bcrypt.hashSync(req.body.password, salt);
//     console.log(hashPass);
//     const updateUser = await UserModel.findByIdAndUpdate(
//       req.params.id,
//       {
//         name: req.body.name,
//         phone: req.body.phone,
//         username: req.body.username,
//         password: hashPass,
//         avatar: avatar,
//       },
//       { new: true }
//     );
//     res.send({
//       status: 200,
//       message: "Successfully Updated",
//       updateUser: updateUser,
//     });
//   } catch (e) {
//     res.send({
//       status: 400,
//       message: `Error: ${e}`,
//     });
//   }
// });

export default router;
