exports.test = content => {
	return (req, res, next) => {
		res.status(200).json(content)
	}
}