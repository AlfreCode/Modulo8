import express from "express"
import { signin, signup } from "../controllers/auth.controller.js"
import { emitToken } from "../middlewares/auth.middleware.js"


const router = express.Router()

router.post("/signup", signup)
router.post("/signin", emitToken, signin)

export default router