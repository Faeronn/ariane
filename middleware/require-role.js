// After authenticateUser: only the listed roles go through, others get 403.
export default function requireRole(...roles) {
	return (request, response, next) => {
		if (!roles.includes(request.user?.role)) return response.status(403).send({ message: 'Error : Forbidden.' });
		return next();
	};
}
