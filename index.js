import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import authRouter from './routes/authRoutes.js'

const app = express()
dotenv.config()


app.use(cors())
app.use(express.json())
app.use('/auth',authRouter)


app.listen(process.env.PORT,()=>{
    console.log("Server is running on port 4000")
})
