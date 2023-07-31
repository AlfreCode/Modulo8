import express from "express"
import {
	findAll,
	createUser,
	findUserById,
	updateUserById,
	deleteUserById
} from "../controllers/user.controller.js"
import { verifyToken } from "../middlewares/auth.middleware.js"


const router = express.Router()

router.get("/", verifyToken, findAll)
router.post("/", createUser)
router.get("/:id", verifyToken, findUserById)
router.put("/:id", verifyToken, updateUserById)
router.delete("/:id", verifyToken, deleteUserById)

export default router