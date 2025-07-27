import { Router } from "express";
import { forgotPassword, getCurrentUser, loginUser, logoutUser, registerUser, resetPassword} from "../controllers/user.controller.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router=Router()

router.route("/register").post(registerUser);
router.route("/login").post(loginUser)
router.route("/logout").post(verifyJWT,logoutUser)
router.route("/forgot-password").post(forgotPassword)
router.route("/reset-password/:token").post(resetPassword)
router.route("/me").get(verifyJWT,getCurrentUser)



export default router;