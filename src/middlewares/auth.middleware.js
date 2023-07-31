import jwt from 'jsonwebtoken'
import User from '../models/user.model.js'
import bcrypt from 'bcrypt'
import 'dotenv'

export const emitToken = async (req, res, next) => {
	try {
		const { email, password } = req.body
		const user = await User.findOne({
			where: { email },
			attributes: ['id', 'firstname', 'lastname', 'email', 'password']
		})

		if (user === null) {
			res.status(400).send({ code: 400, message: 'authentication error' })
		}

		const hashPassword = await bcrypt.compare(password, user.password)

		if (hashPassword) {
			if (user === null) {
				res.status(400).send({ code: 400, message: 'authentication error. check your credentials.' })
			}
		}

		delete user.password

		const token = jwt.sign({
			exp: Math.floor(Date.now() / 1000) + 60 * 10,
			data: user
		}, process.env.SECRET_TOKEN)

		req.token = token
		req.user = user

		next()
	} catch (err) {
		return console.log(`Error de generacion. ${err.message}`)
	}
}

export const verifyToken = async (req, res, next) => {
	try {
		let { token } = req.query
		if (!token) {
			token = req.headers.authorization
			if (!token) {
				return res
					.status(400)
					.send({
						code: 400,
						message: 'Ruta protegida'
					})
			}

			token = token.split(' ')[1]
			if (token.length === 0) {
				throw new Error('se necesita token')
			}
		}

		jwt.verify(token, process.env.SECRET_TOKEN, async (err, decoded) => {
			if (err) {
				return res.status(401).send({
					code: 401,
					message: `error ${err.message}`
				})
			}

			const user = await User.findByPk(decoded.data.id, {
				attributes: ['id', 'firstname', 'lastname', 'email']
			})

			if (!user) {
				return res.status(400).json({
					code: 400,
					message: `Usuario eliminado ${err.message}`
				})
			}

			req.user = user
			next()
		})
	} catch (err) {
		return res.status(401).send({
			code: 401,
			message: `Error de generacion. ${err.message}`
		})
	}
}
