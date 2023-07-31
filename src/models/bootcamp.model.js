import { DataTypes } from "sequelize"
import sequelize from "../config/db.config.js"

const Bootcamp = sequelize.define(
	"bootcamps",
	{
		title: {
			type: DataTypes.STRING(50),
			allowNull: false,
			validate: {
				notEmpty: true
			}
		},
		cue: {
			type: DataTypes.INTEGER,
			allowNull: false,
			defaultValue: 0,
			validate: {
				min: 5,
				max: 10,
				notEmpty: true
			}
		},
		description: {
			type: DataTypes.TEXT,
			allowNull: false,
			validate: {
				notEmpty: true
			}
		}
	},
	{
		timestamps: true,
		tableName: "bootcamps"
	}
)

export default Bootcamp