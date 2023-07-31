import User from './user.model.js'
import Bootcamp from './bootcamp.model.js'

User.belongsToMany(Bootcamp, {
	through: "user_bootcamp",
	as: "bootcamps",
	foreignKey: "user_id"
})

Bootcamp.belongsToMany(User, {
	through: "user_bootcamp",
	as: "users",
	foreignKey: "bootcamp_id"
})