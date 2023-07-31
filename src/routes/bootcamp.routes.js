import express from "express"
import {
	addUser,
	findAll,
	createBootcamp,
	findById
} from "../controllers/bootcamp.controller.js"
import { verifyToken } from "../middlewares/auth.middleware.js"


const router = express.Router()

router.get("/", findAll)
router.post("/", verifyToken, createBootcamp)
router.post("/adduser", verifyToken, addUser)
router.get("/:id", verifyToken, findById)

export default router