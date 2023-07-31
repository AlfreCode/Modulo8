import Bootcamp from "../models/bootcamp.model.js"
import User from "../models/user.model.js"

export const findAll = async (_req, res) => {
	try {
		const users = await User.findAll({
			include: [{
				model: Bootcamp,
				as: 'bootcamps',
				attributes: { exclude: ['createdAt', 'updatedAt'] },
				through: { attributes: [] }
			}]
		})
		res.send({ code: 200, data: users })
	} catch (err) {
		res.status(500).send({
			code: 500,
			message: `💩, Error to get users, ${err}`
		})
	}
}

export const createUser = async (req, res) => {
	try {
		let { firstname, lastname, email } = req.body
		const [user, created] = await User.findOrCreate({
			where: { email },
			defaults: {
				firstname,
				lastname,
				email
			},
		})

		if (!created) {
			return res.status(400).send({
				code: 400,
				message: `User '${user.email}' already exists!`
			})
		}

		res.status(201).send({
			code: 201,
			message: `User '${user.firstname} ${user.lastname}' created!`
		})
	} catch (err) {
		res.status(500).send({
			code: 500,
			message: `💩, Error, ${err.message}`
		})
	}
}

export const findUserById = async (req, res) => {
	try {
		let { id } = req.params
		let found = await User.findByPk(id, {
			include: [{
				model: Bootcamp,
				as: 'bootcamps',
				attributes: { exclude: ['createdAt', 'updatedAt'] },
				through: { attributes: [] }
			}]
		})

		if (!found) {
			return res
				.status(404)
				.send({ code: 404, message: "User not found!" })
		}

		res.status(200).send({
			code: 200,
			message: `User '${found.email}' found!`,
			data: found
		})
	} catch (err) {
		res.status(500).send({
			code: 500,
			message: `💩, Error to to find user by id, ${err.message}`
		})
	}
}

export const updateUserById = async (req, res) => {
	try {
		let { id } = req.params
		let { firstname, lastname } = req.body
		let found = await User.findByPk(id)

		if (!found) {
			return res
				.status(404)
				.send({ code: 404, message: "User not found!" })
		}

		let newUser = await found.update(
			{ firstname, lastname },
			{ where: { id } }
		)

		res.status(200).send({
			code: 200,
			message: `User '${newUser.firstname} ${newUser.lastname}' updated!`,
			data: newUser
		})
	} catch (err) {
		res.status(500).send({
			code: 500,
			message: `💩, Error to update user, ${err.message}`
		})
	}
}

export const deleteUserById = async (req, res) => {
	try {
		let { id } = req.params
		let found = await User.findByPk(id)
		let fullname = `${found.firstname} ${found.lastname}`

		if (!found) {
			return res
				.status(404)
				.send({ code: 404, message: `User not found!` })
		}
		await found.destroy()

		res.status(200).send({
			code: 200,
			message: `User '${fullname}' deleted!`
		})
	} catch (err) {
		res.status(500).send({
			code: 500,
			message: `💩, Error to delete by id, ${err.message}`
		})
	}
}
