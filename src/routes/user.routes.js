import { Router } from "express";
import { changeCurrentPassword, deleteAccount, forgotPassword, getCurrentUser,  googleOAuth, loginUser, logoutUser, msg, refreshAccessToken, registerUser, resetPassword, updateAccountDetails} from "../controllers/user.controller.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router=Router()
router.route("/register").post(registerUser);
router.route("/login").post(loginUser)
router.route("/logout").post(verifyJWT,logoutUser)
router.route("/forgot-password").post(forgotPassword)
router.route("/reset-password/:token").post(resetPassword)
router.route("/me").get(verifyJWT,getCurrentUser)
router.route("/refresh-token").post(verifyJWT,refreshAccessToken)
router.route("/change-password").put(verifyJWT,changeCurrentPassword)
router.route("/update").patch(verifyJWT,updateAccountDetails)
router.route("/delete").delete(verifyJWT,deleteAccount)
router.route("/msg").get(msg)

router.route("/google").get(googleOAuth)



export default router;