import express from "express"
import userRoutes from "./routes/user.routes.js"
import bootcampRoutes from "./routes/bootcamp.routes.js"
import authRoutes from "./routes/auth.routes.js"

const app = express()

app.use(express.json())

//definir rutas
app.use("/api/v1/users", userRoutes)
app.use("/api/v1/bootcamps", bootcampRoutes)
app.use("/api", authRoutes)

export default app