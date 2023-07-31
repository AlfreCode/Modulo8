import User from '../models/user.model.js'
import bcrypt from 'bcrypt'

export const signup = async (req, res) => {
	try {
		const { firstname, lastname, email, password } = req.body

		const salt = bcrypt.genSaltSync(10)
		const hashPassword = bcrypt.hashSync(password, salt)

		const [user, created] = await User.findOrCreate({
			where: { email },
			defaults: {
				firstname, lastname, email, password: hashPassword
			}
		})

		if (!created) {
			return res.status(400).send({
				code: 400,
				message: `User '${user.email}' already exists!`
			})
		}

		res.status(201).send({
			code: 201,
			message: 'User registered successfully'
		})
	} catch (err) {
		return res.status(400).send({
			code: 400,
			message: `💩, Error to register a new User. ${err}`
		})
	}
}

export const signin = async (req, res) => {
	try {
		res.status(200).send({
			code: 200,
			token: req.token,
			user: req.user
		})
	} catch (err) {
		return res.status(400).send({
			code: 400,
			message: `💩, Error to login User. ${err.message}`
		})
	}
}